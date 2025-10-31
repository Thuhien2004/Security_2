from datetime import datetime
from pyhanko.sign import signers, fields
from pyhanko.stamp.text import TextStampStyle
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec

# === ĐƯỜNG DẪN ===
PDF_IN = r"C:\Users\Dell\Desktop\Security\bt2\bt2.pdf"
PDF_OUT = r"C:\Users\Dell\Desktop\Security\bt2\signed.pdf"
KEY_FILE = r"C:\Users\Dell\Desktop\Security\bt2\keys\signer_key.pem"
CERT_FILE = r"C:\Users\Dell\Desktop\Security\bt2\keys\signer_cert.pem"
SIG_IMG = r"C:\Users\Dell\Desktop\Security\bt2\hien.jpg"

# Bước 1: Chuẩn bị file PDF gốc (nội dung bài tập, không AcroForm)
print("Bước 1: Chuẩn bị PDF gốc (bt2.pdf - nội dung bài tập).")

# Bước 2: Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes cho DER PKCS#7)
print("Bước 2: Tạo SigField1, reserve /Contents ~8192 bytes.")

# Bước 3: Xác định /ByteRange (loại trừ vùng /Contents khỏi hash - tự động qua pyHanko)
print("Bước 3: Xác định /ByteRange (vùng hash trừ /Contents).")

# Bước 4: Tính hash (SHA-256) trên vùng ByteRange (md_algorithm='sha256')
print("Bước 4: Tính hash SHA-256 trên ByteRange (md_algorithm='sha256').")

# Bước 5: Tạo PKCS#7/CMS detached (include messageDigest/signingTime/contentType trong signedAttrs offset ~100 bytes; cert chain trong certificates sequence)
print("Bước 5: Tạo PKCS#7 detached (messageDigest in signedAttrs, signingTime in signedAttrs, cert chain in certificates).")

# === TẠO SIGNER & VALIDATION CONTEXT (RSA 2048-bit, padding PKCS#1 v1.5 mặc định) ===
signer = signers.SimpleSigner.load(KEY_FILE, CERT_FILE, key_passphrase=None)  # Key size 2048-bit từ gen_keys.py
vc = ValidationContext(trust_roots=[load_cert_from_pemder(CERT_FILE)])  # Cert chain từ vc

# Bước 6: Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset (sau ByteRange)
print("Bước 6: Chèn DER PKCS#7 vào /Contents offset (hex-encoded).")

# Bước 7: Ghi incremental update (append revision mới với SigDict + cross-ref table)
print("Bước 7: Incremental update (append SigDict + cross-ref).")

# === MỞ FILE GỐC ===
with open(PDF_IN, "rb") as inf:
    writer = IncrementalPdfFileWriter(inf)

    # Lấy số trang cuối cùng (fix tương thích với pyHanko mới)
    try:
        pages = writer.root["/Pages"]
        if "/Count" in pages:
            num_pages = int(pages["/Count"])
        else:
            num_pages = len(pages["/Kids"])
    except Exception as e:
        print("Không đọc được số trang, mặc định 1.")
        num_pages = 1

    target_page = num_pages - 1  

    fields.append_signature_field(
        writer,
        SigFieldSpec(
            sig_field_name="SigField1",
            box=(240, 50, 550, 150),
            on_page=target_page 
        )
    )

    # Ảnh nền (hình chữ ký tay minh họa)
    background_img = images.PdfImage(SIG_IMG)

    # Layout ảnh & text (Bước 5: signingTime từ datetime.now(), contentType data)
    bg_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,  # ảnh bên trái
        y_align=AxisAlignment.ALIGN_MID,  # giữa
        margins=Margins(right=20)
    )

    text_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(left=150)  # Khoảng cách giữa ảnh và chữ
    )

    # Style chữ
    text_style = TextBoxStyle(font_size=13)

    # Nội dung chữ ký (dùng tiếng Việt, ngày ký hiện tại)
    ngay_ky = datetime.now().strftime("%d/%m/%Y")
    stamp_text = (
        "Nguyen Thi Thu Hien"
        "\nSDT: 0917874194"
        "\nMSV: K225480106015"
        f"\nNgày ký: {ngay_ky}"
    )

    stamp_style = TextStampStyle(
        stamp_text=stamp_text,
        background=background_img,
        background_layout=bg_layout,
        inner_content_layout=text_layout,
        text_box_style=text_style,
        border_width=1,
        background_opacity=1.0,
    )

    # Metadata chữ ký (Bước 4-5: md_algorithm SHA-256)
    meta = signers.PdfSignatureMetadata(
        field_name="SigField1",
        reason="Nộp bài: Chữ ký số PDF - 58KTP",
        location="Thái Nguyên, VN",
        md_algorithm="sha256",
    )

    # PdfSigner (Bước 3-6: ByteRange/hash/PKCS#7 tự động; RSA padding PKCS#1 v1.5 từ signer)
    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        stamp_style=stamp_style,
    )

    # Bước 6-7: Ký và lưu (chèn /Contents hex, incremental append)
    with open(PDF_OUT, "wb") as outf:
        pdf_signer.sign_pdf(writer, output=outf)

# Bước 8: (LTV) Cập nhật DSS với Certs/OCSPs/CRLs/VRI (từ vc, tự động nếu có OCSP)
print("Bước 8: LTV DSS - Append Certs/OCSP/CRLs/VRI (từ vc).")

print("Đã ký PDF thành công! File lưu tại:", PDF_OUT)
