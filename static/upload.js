document.addEventListener('DOMContentLoaded', function() {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const previewContainer = document.getElementById('preview-container');
    const previewImage = document.getElementById('preview-image');
    const uploadContent = document.querySelector('.upload-content');
    const removeBtn = document.getElementById('remove-btn');
    const submitBtn = document.getElementById('submit-btn');
    const uploadForm = document.getElementById('upload-form');
    const uploadProgress = document.getElementById('upload-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');

    let selectedFile = null;

    uploadZone.addEventListener('click', function(e) {
        if (e.target !== removeBtn && !removeBtn.contains(e.target)) {
            fileInput.click();
        }
    });

    uploadZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    fileInput.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    removeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        clearFile();
    });

    function handleFile(file) {
        const allowedTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/tiff'];
        
        if (!allowedTypes.includes(file.type)) {
            alert('Please select a valid image file (PNG, JPG, WebP, or TIFF)');
            return;
        }

        if (file.size > 15 * 1024 * 1024) {
            alert('File size must be less than 15MB');
            return;
        }

        selectedFile = file;
        
        const reader = new FileReader();
        reader.onload = function(e) {
            previewImage.src = e.target.result;
            uploadContent.style.display = 'none';
            previewContainer.style.display = 'block';
            submitBtn.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    function clearFile() {
        selectedFile = null;
        fileInput.value = '';
        previewImage.src = '';
        uploadContent.style.display = 'block';
        previewContainer.style.display = 'none';
        submitBtn.disabled = true;
    }

    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        if (!selectedFile) {
            alert('Please select an image first');
            return;
        }

        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('factor', document.querySelector('input[name="factor"]:checked').value);
        formData.append('preset', document.getElementById('preset').value);
        formData.append('denoise', document.getElementById('denoise').value);

        submitBtn.querySelector('.btn-text').style.display = 'none';
        submitBtn.querySelector('.btn-loading').style.display = 'inline';
        submitBtn.disabled = true;
        uploadProgress.style.display = 'block';

        const xhr = new XMLHttpRequest();
        
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressFill.style.width = percentComplete + '%';
                progressText.textContent = 'Uploading... ' + Math.round(percentComplete) + '%';
            }
        });

        xhr.addEventListener('load', function() {
            if (xhr.status === 202) {
                const response = JSON.parse(xhr.responseText);
                progressText.textContent = 'Upload complete! Redirecting...';
                setTimeout(function() {
                    window.location.href = '/job/' + response.job_id;
                }, 500);
            } else {
                let errorMsg = 'Upload failed';
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMsg = response.error || errorMsg;
                } catch (e) {}
                
                alert(errorMsg);
                resetForm();
            }
        });

        xhr.addEventListener('error', function() {
            alert('Upload failed. Please try again.');
            resetForm();
        });

        xhr.open('POST', '/api/v1/uploads');
        xhr.send(formData);
    });

    function resetForm() {
        submitBtn.querySelector('.btn-text').style.display = 'inline';
        submitBtn.querySelector('.btn-loading').style.display = 'none';
        submitBtn.disabled = false;
        uploadProgress.style.display = 'none';
        progressFill.style.width = '0%';
    }
});
