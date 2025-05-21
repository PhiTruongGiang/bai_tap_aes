# app.py
from flask import Flask, request, render_template, send_file, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256 # Để derive key từ mật khẩu
import io
import os

app = Flask(__name__)
# Thiết lập một khóa bí mật cho Flask sessions để flash message hoạt động
app.secret_key = os.urandom(24) 
app.config['UPLOAD_FOLDER'] = 'uploads' 
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024 # Tăng giới hạn lên 32MB nếu cần

# Tạo thư mục uploads nếu chưa có khi khởi động ứng dụng
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Hàm derive key (tạo khóa từ mật khẩu) ---
def derive_key(password_str):
    """
    Tạo khóa AES 256-bit (32 bytes) từ mật khẩu người dùng.
    Sử dụng SHA256 cho mục đích demo.
    """
    return sha256(password_str.encode('utf-8')).digest()

# --- Hàm mã hóa file ---
def encrypt_file(file_stream, password_str):
    try:
        key = derive_key(password_str)
        # AES.MODE_CBC cần một IV (Initialization Vector) 16 bytes ngẫu nhiên
        iv = get_random_bytes(AES.block_size) 
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Đọc toàn bộ dữ liệu file từ stream
        plaintext_data = file_stream.read()
        
        # Đệm dữ liệu để có độ dài là bội số của block_size (16 bytes)
        padded_data = pad(plaintext_data, AES.block_size)
        
        # Mã hóa
        encrypted_data = cipher.encrypt(padded_data)
        
        # Trả về IV + dữ liệu đã mã hóa. IV là cần thiết để giải mã sau này.
        return iv + encrypted_data
    except Exception as e:
        print(f"Lỗi khi mã hóa: {e}")
        return None

# --- Hàm giải mã file ---
def decrypt_file(file_stream, password_str):
    try:
        key = derive_key(password_str)
        
        # Đọc 16 byte đầu tiên làm IV
        iv = file_stream.read(AES.block_size)
        if len(iv) != AES.block_size:
            raise ValueError("Dữ liệu không đủ để trích xuất IV hoặc không phải file đã mã hóa đúng định dạng.")
        
        # Đọc phần còn lại là dữ liệu đã mã hóa
        encrypted_content = file_stream.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Giải mã
        decrypted_padded_data = cipher.decrypt(encrypted_content)
        
        # Bỏ đệm dữ liệu sau khi giải mã
        original_data = unpad(decrypted_padded_data, AES.block_size)
        
        return original_data
    except ValueError as e:
        # Lỗi padding thường do sai mật khẩu hoặc file không hợp lệ
        if "Padding is incorrect" in str(e) or "Incorrect padding" in str(e):
            print("Lỗi giải mã: Khóa không đúng hoặc file bị hỏng/không đúng định dạng.")
            return None 
        print(f"Lỗi giải mã (ValueError): {e}")
        return None
    except Exception as e:
        print(f"Lỗi chung khi giải mã: {e}")
        return None

# --- Các route của Flask ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    if 'file' not in request.files:
        flash("Không có file được chọn.")
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')

    if file.filename == '':
        flash("Không có file được chọn.")
        return redirect(url_for('index'))
    
    if not password:
        flash("Vui lòng nhập mật khẩu.")
        return redirect(url_for('index'))

    # Kiểm tra kích thước file trước khi đọc vào bộ nhớ để tránh tràn RAM với file lớn
    if file.content_length > app.config['MAX_CONTENT_LENGTH']:
        flash(f"File quá lớn. Kích thước tối đa cho phép là {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.0f}MB.")
        return redirect(url_for('index'))

    # Đọc dữ liệu file vào một luồng BytesIO
    file_stream = io.BytesIO(file.read())
    
    encrypted_content = encrypt_file(file_stream, password)

    if encrypted_content:
        # Tạo một luồng byte để gửi file đã mã hóa
        encrypted_stream = io.BytesIO(encrypted_content)
        
        # Đổi tên file để dễ nhận biết là đã mã hóa
        # Ví dụ: mydoc.txt -> mydoc.txt.aes
        filename_base, file_extension = os.path.splitext(file.filename)
        download_filename = filename_base + file_extension + ".aes"
        
        return send_file(
            encrypted_stream,
            mimetype='application/octet-stream', # Kiểu MIME chung cho file binary
            as_attachment=True, # Buộc trình duyệt tải về
            download_name=download_filename
        )
    else:
        flash("Lỗi trong quá trình mã hóa. Vui lòng kiểm tra file và mật khẩu.")
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    if 'file' not in request.files:
        flash("Không có file được chọn.")
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')

    if file.filename == '':
        flash("Không có file được chọn.")
        return redirect(url_for('index'))
    
    if not password:
        flash("Vui lòng nhập mật khẩu.")
        return redirect(url_for('index'))

    # Kiểm tra kích thước file
    if file.content_length > app.config['MAX_CONTENT_LENGTH']:
        flash(f"File quá lớn. Kích thước tối đa cho phép là {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.0f}MB.")
        return redirect(url_for('index'))

    # Đọc dữ liệu file vào một luồng BytesIO
    file_stream = io.BytesIO(file.read())
    
    decrypted_content = decrypt_file(file_stream, password)

    if decrypted_content is not None:
        decrypted_stream = io.BytesIO(decrypted_content)
        
        # Cố gắng khôi phục tên file gốc
        original_filename = file.filename
        if original_filename.endswith('.aes'):
            # Nếu file có đuôi .aes, loại bỏ nó
            original_filename = original_filename[:-4] 
        else:
            # Nếu không có đuôi .aes, thêm .decrypted để tránh ghi đè hoặc nhận diện
            original_filename += ".decrypted"

        return send_file(
            decrypted_stream,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=original_filename
        )
    else:
        flash("Lỗi trong quá trình giải mã. Khóa không đúng hoặc file bị hỏng.")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000) # Chạy trên port 5000