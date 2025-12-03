# Single-Page Website Project

## Overview
A lightweight, responsive single-page website built with pure HTML5 and CSS3. The project follows modern web development best practices with minimal JavaScript usage.

## Project Structure
```
/
├── index.html      # Main HTML file with semantic structure
├── styles.css      # Complete CSS styling with responsive design
├── server.py       # Simple Python HTTP server for development
└── replit.md       # Project documentation
```

## Features
- **Semantic HTML5**: Clean, accessible markup structure
- **CSS3 Styling**: Modern flexbox and grid layouts
- **Responsive Design**: Mobile-first approach with breakpoints for tablet and desktop
- **CSS-Only Navigation**: Hamburger menu without JavaScript
- **Smooth Scroll**: Native CSS smooth scrolling behavior
- **Accessibility**: ARIA labels, semantic tags, and reduced motion support
- **Performance**: No external dependencies, inline SVG icons

## Sections
1. **Header**: Fixed navigation with responsive hamburger menu
2. **Hero**: Full-viewport welcome section with call-to-action
3. **About**: Company information with feature list
4. **Services**: 4-column grid showcasing offerings
5. **Portfolio**: Project showcase with hover effects
6. **Contact**: Contact form with HTML5 validation
7. **Footer**: Brand info, quick links, and social icons

## CSS Features
- CSS Custom Properties (variables) for consistent theming
- Flexbox and CSS Grid for layouts
- CSS transitions and transforms for animations
- Media queries for responsive breakpoints
- Prefers-reduced-motion support

## Development
The server runs on port 5000 using Python's built-in HTTP server with cache-control headers disabled for development.

## Customization Guide

### Changing Colors
Edit the CSS custom properties in `:root` at the top of `styles.css`:
```css
:root {
    --primary-color: #6366f1;    /* Main brand color */
    --primary-dark: #4f46e5;     /* Darker variant for hover states */
    --secondary-color: #1e293b;  /* Text and footer background */
}
```

### Adding New Sections
1. Add HTML section in `index.html` following the pattern:
```html
<section class="section-name" id="section-id">
    <div class="container">
        <h2 class="section-title">Section Title</h2>
        <!-- Content here -->
    </div>
</section>
```
2. Add corresponding styles in `styles.css`
3. Update navigation links in header and footer

### Responsive Breakpoints
- Desktop: > 1024px
- Tablet: 768px - 1024px
- Mobile: < 768px
- Small Mobile: < 480px

## Recent Changes
- December 2024: Initial project setup with all core sections
