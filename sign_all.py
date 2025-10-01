#!/usr/bin/env python3
import os
import glob
from datetime import datetime, timezone
from pypdf import PdfReader
from endesive import pdf
from OpenSSL import crypto  # provisto por pyOpenSSL
from cryptography.hazmat.primitives.serialization import pkcs12


def get_page_size(pdf_path: str, page_index: int = -1):
    """
    Parameters
    ----------
    pdf_path : str
        Ruta del PDF.
    page_index : int
        Índice de página (0=primera; -1=última).

    Returns
    -------
    tuple[float, float]
        (ancho_pts, alto_pts) en puntos PDF.
    """
    reader = PdfReader(pdf_path)
    if page_index < 0:
        page_index = len(reader.pages) - 1
    page = reader.pages[page_index]
    # Nota: mediabox siempre en puntos; origen abajo-izquierda
    width = float(page.mediabox.width)
    height = float(page.mediabox.height)
    # Si el PDF trae rotación, podrías compensarla; por simplicidad, devolvemos tal cual
    return width, height


def compute_bottom_right_box(
    width: float,
    height: float,
    box_w: float = 160,
    box_h: float = 84,
    margin_right: float = 24,
    margin_bottom: float = 24,
):
    """
    Calcula una caja en la esquina inferior derecha.

    Returns
    -------
    tuple[float, float, float, float]
        (x1, y1, x2, y2) en puntos.
    """
    x2 = width - margin_right
    x1 = x2 - box_w
    y1 = margin_bottom
    y2 = y1 + box_h
    return (x1, y1, x2, y2)


def _load_pkcs12(p12_path: str, password: str):
    """
    Cargar clave privada, certificado y CA desde archivo PKCS#12 (.p12/.pfx)
    usando cryptography en lugar de pyOpenSSL.
    """
    with open(p12_path, "rb") as fh:
        p12_data = fh.read()

    key, cert, additional_certs = pkcs12.load_key_and_certificates(
        p12_data, password.encode("utf-8")
    )
    return key, cert, additional_certs or []


def _signature_dict(
    visible: bool,
    page_index: int = -1,
    box=(36, 36, 196, 120),
    reason="Aprobación de documento",
    location="Sabadell, ES",
    contact="it@empresa.com",
):
    """
    Parameters
    ----------
    visible : bool
        If True, crea un cuadro visible de firma.
    page_index : int
        Índice de página para la firma (0 = primera, -1 = última).
    box : tuple
        (x1, y1, x2, y2) en puntos PDF (1/72 pulgadas) desde esquina inferior-izquierda.
    reason : str
        Motivo que aparecerá en la firma.
    location : str
        Ubicación para la firma.
    contact : str
        Contacto del firmante.

    Returns
    -------
    dict
        Diccionario de configuración para endesive.pdf.cms.sign
    """
    # Fecha en formato PDF (UTC)
    signing_date = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "sigflags": 3,  # firma aprobatoria
        "contact": contact,
        "location": location,
        "signingdate": signing_date,
        "reason": reason,
        "signature": "Firma Digital: ENZO GAROFALO LANZUISI",  # nombre del campo/entrada
    }
    if visible:
        # Hacer visible la firma en la página indicada
        dct["sigpage"] = page_index
        dct["signaturebox"] = box
    return dct


def sign_pdf_file(
    input_path: str,
    output_path: str,
    p12_path: str,
    p12_password: str,
    visible: bool = False,
    page_index: int = -1,
    box=(36, 36, 196, 120),
):
    """
    Firmar un PDF con PKCS#12 utilizando endesive.

    Parameters
    ----------
    input_path : str
        Path del PDF de entrada.
    output_path : str
        Path del PDF firmado de salida.
    p12_path : str
        Path absoluto del archivo .p12/.pfx.
    p12_password : str
        Contraseña del PKCS#12.
    visible : bool
        Si True, coloca firma visible en `page_index` y `box`.
    page_index : int
        Página destino (0=primera, -1=última).
    box : tuple
        Caja (x1,y1,x2,y2) en puntos PDF.

    Returns
    -------
    None
    """
    # Leer bytes del PDF
    with open(input_path, "rb") as fh:
        pdf_bytes = fh.read()

    # Cargar llaves y certificados desde PKCS#12
    key, cert, ca = _load_pkcs12(p12_path, p12_password)

    # Si se quiere firma visible, recalculamos la caja en la esquina inferior derecha
    if visible:
        width, height = get_page_size(input_path, page_index)
        box = compute_bottom_right_box(
            width, height, box_w=160, box_h=84, margin_right=24, margin_bottom=24
        )

    # Preparar diccionario de firma (visible o invisible)
    dct = _signature_dict(visible=visible, page_index=page_index, box=box)

    # Firmar (algoritmo por defecto SHA256)
    # Nota: endesive espera (data, dct, key, cert, ca_list, 'sha256', timestamp_url)
    signed_bytes = pdf.cms.sign(pdf_bytes, dct, key, cert, ca, "sha256")

    # Guardar PDF firmado por incremento (append de la firma)
    with open(output_path, "wb") as fh:
        fh.write(pdf_bytes)
        fh.write(signed_bytes)


def sign_all_pdfs(
    source_dir: str = "docs",
    target_dir: str = "signed",
    p12_path: str = "/mnt/c/Users/egarofalo/source/repos/firma-digital/mi_certificado.p12",
    p12_password: str = "holacaracola",
    visible: bool = False,
):
    """
    Firma todos los PDF de `source_dir` y los guarda en `target_dir`.

    Parameters
    ----------
    source_dir : str
        Carpeta de origen con PDFs.
    target_dir : str
        Carpeta de salida para PDFs firmados.
    p12_path : str
        Ruta absoluta al .p12 (en WSL, usa /mnt/c/...).
    p12_password : str
        Contraseña del certificado.
    visible : bool
        Si True, firma visible en la última página.

    Returns
    -------
    None
    """
    # Crear carpeta destino si no existe
    os.makedirs(target_dir, exist_ok=True)

    # Buscar PDFs y firmar uno a uno
    for pdf_path in glob.glob(os.path.join(source_dir, "*.pdf")):
        base = os.path.basename(pdf_path)
        out_path = os.path.join(target_dir, base)
        # Por defecto, visible=False (firma invisible). Cambia visible=True si quieres sello.
        sign_pdf_file(
            input_path=pdf_path,
            output_path=out_path,
            p12_path=p12_path,
            p12_password=p12_password,
            visible=visible,
            page_index=-1,  # -1 = última página si visible=True
            box=(36, 36, 196, 120),  # ajusta la caja si haces visible=True
        )
        print(f"✔ Firmado: {base}")


if __name__ == "__main__":
    # Ejecuta: python sign_all.py
    sign_all_pdfs(
        source_dir="docs",
        target_dir="signed",
        p12_path="digital_certificate.p12",
        p12_password="holacaracola",
        visible=True,
    )
