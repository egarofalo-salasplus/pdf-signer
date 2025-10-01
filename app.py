# -*- coding: utf-8 -*-
# Variables en inglés; comentarios en español (como prefieres)

import io
import zipfile
from datetime import datetime, timezone
from typing import List, Tuple

import streamlit as st
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf
from pypdf import PdfReader

# -------------------------------
# Utilidades de PKCS#12 y firma
# -------------------------------


def load_pkcs12_from_bytes(p12_bytes: bytes, password: str):
    """
    Cargar clave privada, certificado y cadena (CA) desde un PKCS#12 en memoria.
    """
    key, cert, ca_list = pkcs12.load_key_and_certificates(
        p12_bytes, password.encode("utf-8") if password else None
    )
    return key, cert, ca_list or []


def signature_dict(
    visible: bool,
    page_index: int = -1,
    box: Tuple[float, float, float, float] = (36, 36, 196, 120),
    reason: str = "Aprobación de documento",
    location: str = "Sabadell, ES",
    contact: str = "it@empresa.com",
):
    """
    Construir el diccionario de parámetros de firma para endesive.
    """
    signing_date = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "sigflags": 3,
        "contact": contact,
        "location": location,
        "signingdate": signing_date,
        "reason": reason,
        "signature": "FIRMA DIGITAL: ENZO GAROFALO LANZUISI",  # nombre del campo/entrada
    }
    if visible:
        dct["sigpage"] = page_index
        dct["signaturebox"] = box
    return dct


# -------------------------------
# Cálculo de caja en esquina inf. derecha
# -------------------------------


def get_page_size(pdf_bytes: bytes, page_index: int = -1) -> Tuple[float, float]:
    """
    Obtener tamaño de página en puntos (1/72") del PDF.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    if page_index < 0:
        page_index = len(reader.pages) - 1
    page = reader.pages[page_index]
    width = float(page.mediabox.width)
    height = float(page.mediabox.height)
    return width, height


def bottom_right_box(
    width: float,
    height: float,
    box_w: float = 160,
    box_h: float = 84,
    margin_right: float = 24,
    margin_bottom: float = 24,
) -> Tuple[float, float, float, float]:
    """
    Calcular la caja (x1,y1,x2,y2) para esquina inferior derecha.
    Origen PDF: esquina inferior izquierda.
    """
    x2 = width - margin_right
    x1 = x2 - box_w
    y1 = margin_bottom
    y2 = y1 + box_h
    return (x1, y1, x2, y2)


# -------------------------------
# Firma de un PDF (bytes -> bytes firmados)
# -------------------------------


def sign_pdf_bytes(
    pdf_bytes: bytes,
    key,
    cert,
    ca_list: List,
    visible: bool = False,
    page_index: int = -1,
    br_box: Tuple[float, float, float, float] = None,
    reason: str = "Aprobación de documento",
    location: str = "Sabadell, ES",
    contact: str = "it@empresa.com",
) -> bytes:
    """
    Firmar un PDF en memoria usando endesive (firma incremental).
    Devuelve nuevos bytes del PDF firmado.
    """
    if visible:
        # Si no viene la caja, calcularla para la última página
        if br_box is None:
            width, height = get_page_size(pdf_bytes, page_index)
            br_box = bottom_right_box(width, height)
        dct = signature_dict(
            visible=True,
            page_index=page_index,
            box=br_box,
            reason=reason,
            location=location,
            contact=contact,
        )
    else:
        dct = signature_dict(
            visible=False,
            page_index=page_index,
            reason=reason,
            location=location,
            contact=contact,
        )

    # Generar el bloque CMS de firma
    signed_append = pdf.cms.sign(pdf_bytes, dct, key, cert, ca_list, "sha256")

    # Devolver el PDF original + la firma incremental
    out = io.BytesIO()
    out.write(pdf_bytes)
    out.write(signed_append)
    return out.getvalue()


# -------------------------------
# UI Streamlit
# -------------------------------

st.set_page_config(page_title="PDF Signer", page_icon="✅", layout="centered")
st.title("PDF Signer (Streamlit)")

st.markdown(
    "Sube tu certificado **.p12/.pfx**, introduce la contraseña y selecciona múltiples PDF. "
    "Puedes elegir firma **visible** en la **última página** (esquina inferior derecha) o **invisible**."
)

with st.sidebar:
    st.header("Certificado (.p12 / .pfx)")
    p12_file = st.file_uploader("subir .p12 / .pfx", type=["p12", "pfx"])
    p12_password = st.text_input("Contraseña", type="password")

    st.header("Obciones de firma")
    visible = st.checkbox(
        "Firma visible (abajo a la derecha, última página)", value=True
    )

    # Parámetros para caja visible
    box_w = st.number_input(
        "Ancho de caja (pt)", min_value=60, max_value=600, value=160
    )
    box_h = st.number_input("alto de caja(pt)", min_value=30, max_value=400, value=84)
    margin_right = st.number_input(
        "Margen derecho (pt)", min_value=0, max_value=200, value=24
    )
    margin_bottom = st.number_input(
        "Margen Izquierod (pt)", min_value=0, max_value=200, value=24
    )

    st.subheader("Metadata")
    reason = st.text_input("Razón", value="Aprobación de documento")
    location = st.text_input("Ubicación", value="Sabadell, ES")
    contact = st.text_input("Contacto", value="it@empresa.com")

st.subheader("Subir PDF(s) a firmar")
pdf_files = st.file_uploader(
    "Selecciona uno o más archivos PDF", type=["pdf"], accept_multiple_files=True
)

if pdf_files:
    st.write("Archivos cargados:")
    for f in pdf_files:
        st.write(f"📄 {f.name}")


run = st.button("Firmar PDFs")

if run:
    # Validaciones básicas
    if not p12_file or p12_password is None:
        st.error("Sube el certificado .p12/.pfx y escribe la contraseña.")
    elif not pdf_files:
        st.error("Sube al menos un PDF.")
    else:
        try:
            # Cargar PKCS#12
            p12_bytes = p12_file.read()
            key, cert, ca_list = load_pkcs12_from_bytes(p12_bytes, p12_password)

            signed_results = []  # [(filename, bytes), ...]
            for uploaded in pdf_files:
                original_name = uploaded.name
                pdf_bytes = uploaded.read()

                br = None
                if visible:
                    # Pre-calcular caja para este PDF (puede variar por tamaño de página)
                    w, h = get_page_size(pdf_bytes, -1)
                    br = bottom_right_box(
                        w,
                        h,
                        box_w=float(box_w),
                        box_h=float(box_h),
                        margin_right=float(margin_right),
                        margin_bottom=float(margin_bottom),
                    )

                signed_bytes = sign_pdf_bytes(
                    pdf_bytes=pdf_bytes,
                    key=key,
                    cert=cert,
                    ca_list=ca_list,
                    visible=visible,
                    page_index=-1,
                    br_box=br,
                    reason=reason,
                    location=location,
                    contact=contact,
                )

                # Nombre de salida
                out_name = (
                    original_name[:-4] + "_firmado.pdf"
                    if original_name.lower().endswith(".pdf")
                    else original_name + "_firmado.pdf"
                )
                signed_results.append((out_name, signed_bytes))

            st.success(f"Firmados {len(signed_results)} documento(s). Descarga abajo:")

            # Botones de descarga individuales
            for out_name, data in signed_results:
                st.download_button(
                    label=f"Descargar {out_name}",
                    data=data,
                    file_name=out_name,
                    mime="application/pdf",
                )

            # Botón de descarga ZIP
            if len(signed_results) > 1:
                mem_zip = io.BytesIO()
                with zipfile.ZipFile(
                    mem_zip, "w", compression=zipfile.ZIP_DEFLATED
                ) as zf:
                    for out_name, data in signed_results:
                        zf.writestr(out_name, data)
                mem_zip.seek(0)
                st.download_button(
                    label="Descargar todo como ZIP",
                    data=mem_zip.getvalue(),
                    file_name="pdfs_firmados.zip",
                    mime="application/zip",
                )

        except Exception as e:
            st.error(f"Error firmando PDFs: {e}")
            st.stop()

st.caption(
    "Nota: Coordenadas en puntos PDF (1 pt = 1/72”). Origen en esquina inferior izquierda."
)
