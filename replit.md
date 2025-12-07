# ImageUpscalerPro

## Overview
A complete image upscaling web service built with Flask backend, featuring user upload functionality, image upscaling (2x/4x), job queue processing, admin panel for job management, and SQLite database storage.

## Project Structure
```
/
├── app.py                           # Flask backend with all API endpoints
├── templates/
│   ├── public/
│   │   ├── index.html              # Landing page
│   │   ├── upload.html             # Image upload interface
│   │   └── job_status.html         # Job progress/result page
│   └── admin/
│       ├── login.html              # Admin login
│       ├── dashboard.html          # Admin overview
│       ├── jobs.html               # Job list management
│       ├── job_detail.html         # Single job details
│       ├── settings.html           # System settings
│       └── audit.html              # Audit log viewer
├── static/
│   ├── styles.css                  # Public website styles
│   ├── admin.css                   # Admin panel styles
│   └── upload.js                   # Upload form JavaScript
├── uploads/                         # Original uploaded images
├── results/                         # Upscaled result images
├── imageupscaler.db                # SQLite database (auto-created)
└── replit.md                        # Project documentation
```

## Features

### Public Website
- Modern landing page with feature highlights
- Drag-and-drop image upload interface
- 2x and 4x upscale factor options
- Preset modes (Standard, Photo, Art, Face)
- Denoise levels (None, Low, Medium, High)
- Real-time job status tracking with progress bar
- Downloadable upscaled results

### Admin Panel
- Secure login system with hashed passwords
- Dashboard with statistics:
  - Queued jobs count
  - Running jobs count
  - Completed today count
  - Average processing time
  - Total uploads
  - Storage usage
- Job management:
  - Filter by status
  - View job details
  - Cancel running jobs
  - Requeue failed/completed jobs
- Settings management for system configuration
- Audit log for tracking all admin actions

### Image Processing
- Uses Pillow (PIL) for image manipulation
- Lanczos resampling for high-quality upscaling
- Optional denoising with Gaussian blur + UnsharpMask
- Supports PNG, JPG, WebP, TIFF formats
- Background thread processing for non-blocking uploads

## Getting Started

### Running the App
The Flask app runs on port 5000. Access the website at the root URL.

### Admin Credentials
- **Username:** abdullah
- **Password:** 231980077

### Using the Service
1. Go to the Upload page
2. Drag & drop or click to select an image
3. Choose upscale factor (2x or 4x)
4. Select preset and denoise options
5. Click "Start Upscaling"
6. Wait for processing to complete
7. Download your upscaled image

## API Endpoints

### Public API
- `GET /` - Landing page
- `GET /upload` - Upload page
- `GET /job/<job_id>` - Job status page
- `POST /api/v1/uploads` - Upload image and create job
- `GET /api/v1/jobs/<job_id>` - Get job status JSON
- `GET /api/v1/health` - System health check
- `GET /uploads/<filename>` - Serve original images
- `GET /results/<filename>` - Serve result images

### Admin API
- `GET /admin/login` - Admin login page
- `POST /admin/login` - Submit credentials
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/jobs` - Job list
- `GET /admin/jobs/<job_id>` - Job details
- `GET /admin/settings` - Settings page
- `GET /admin/audit` - Audit logs
- `GET /admin/logout` - Logout
- `POST /api/v1/admin/jobs/<job_id>/cancel` - Cancel job
- `POST /api/v1/admin/jobs/<job_id>/requeue` - Requeue job
- `POST /api/v1/admin/settings` - Update settings

## Database Schema

### Tables
- **users** - Admin accounts with hashed passwords
- **uploads** - Original file metadata (path, size, dimensions)
- **jobs** - Processing jobs (status, params, results)
- **models** - Available upscaling models
- **settings** - System configuration key-value pairs
- **audit_logs** - Admin action tracking

## Technical Details

### Image Processing Pipeline
1. File uploaded and validated (type, size)
2. Job created with 'queued' status
3. Background thread starts processing
4. Image loaded and resized with Lanczos
5. Optional denoising applied
6. Result saved as optimized PNG
7. Job updated to 'completed'

### Security
- Passwords hashed with werkzeug.security
- Session-based authentication
- Admin-only route protection
- Audit logging for all admin actions
- File type validation
- Size limits enforced

## Configuration

### Environment Variables
- `SESSION_SECRET` - Flask session key (auto-generated if not set)

### Default Settings (in database)
- Max upload size: 15MB
- Allowed MIME types: image/png, image/jpeg, image/webp, image/tiff
- Default model: bicubic
- Rate limit: 10 per minute
- Retention days: 30

## Deployment Notes
- Use production WSGI server (gunicorn) for deployment
- Set SESSION_SECRET environment variable
- Configure proper database backups
- Consider adding rate limiting middleware
- Set up file cleanup cron job for old uploads

## Recent Changes
- December 2024: Complete ImageUpscalerPro service built
- Flask backend with SQLite database
- Public upload and job tracking
- Admin panel with dashboard, job management, settings, audit logs
- PIL-based image upscaling with Lanczos resampling
