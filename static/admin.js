document.addEventListener('DOMContentLoaded', function() {
    const editableFields = document.querySelectorAll('.editable-field');
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-section');

    // Section Navigation
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const sectionId = this.getAttribute('href').substring(1);
            
            // Remove active class from all nav items and sections
            navItems.forEach(nav => nav.classList.remove('active'));
            contentSections.forEach(section => section.classList.remove('active'));
            
            // Add active class to clicked nav item and corresponding section
            this.classList.add('active');
            document.getElementById(sectionId).classList.add('active');
        });
    });

    // Auto-save content
    editableFields.forEach(field => {
        const charCountEl = field.nextElementSibling;
        
        // Update char count on input
        if (charCountEl && charCountEl.classList.contains('char-count')) {
            field.addEventListener('input', function() {
                charCountEl.textContent = this.value.length + ' / ' + (this.maxLength || '∞');
            });
            // Initialize char count
            charCountEl.textContent = field.value.length + ' / ' + (field.maxLength || '∞');
        }
        
        // Track changes
        field.addEventListener('change', function() {
            saveContent(this);
        });
        
        // Visual feedback for unsaved changes
        field.addEventListener('input', function() {
            this.classList.add('modified');
            this.classList.remove('saved');
        });
    });

    function saveContent(field) {
        const section = field.getAttribute('data-section');
        const key = field.getAttribute('data-key');
        const value = field.value;

        fetch('/api/admin/content', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                section_id: section,
                content_key: key,
                content_value: value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                field.classList.remove('modified');
                field.classList.add('saved');
                
                // Remove saved state after 2 seconds
                setTimeout(() => {
                    field.classList.remove('saved');
                }, 2000);
            }
        })
        .catch(error => console.error('Error:', error));
    }
});
