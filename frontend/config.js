// PDFverse Configuration
window.PDFVERSE_CONFIG = {
    API_URL: window.location.hostname === 'localhost' 
        ? 'http://localhost:5000/api'
        : 'https://pdfverse-production.up.railway.app/api'
};    
