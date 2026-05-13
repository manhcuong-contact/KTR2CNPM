# WebChat - Multipurpose Messaging Platform

## Tính năng

- **Auth**: đăng ký, đăng nhập, đăng nhập Google 
- **Chat 1:1**: nhắn tin riêng, voice/video realtime
- **Chat 1:N**: channel chỉ admin được gửi tin
- **Chat N:N**: group nhiều người tương tác tự do
- **File uploads**: đính kèm file và xem preview/download
- **UI**: dark glassmorphism, sidebar 3 tab, empty state

## Dữ liệu lưu ở đâu

- **SQLite**: `webchat.db`
- **Upload files**: `storage/uploads/`
- **Sessions**: lưu trong SQLite bảng `sessions`

## Chạy ứng dụng

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Mở:

- `http://127.0.0.1:8000`

## Ghi chú

- Google login hiện là flow demo qua backend endpoint `/api/auth/google`.
- Ứng dụng dùng WebSocket để nhận realtime message, presence và signaling cuộc gọi.
- Mở 2 tab với 2 tài khoản khác nhau để test chat và voice/video.

## API chính

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/google`
- `GET /api/auth/me`
- `GET /api/conversations`
- `POST /api/conversations/direct`
- `POST /api/conversations`
- `GET /api/conversations/{id}/messages`
- `POST /api/conversations/{id}/messages`
- `POST /api/uploads`
- `WS /ws?token=...`
