// PDFverse Configuration
// ⚠️ UPDATE THIS URL after deploying your backend to Render!

window.PDFVERSE_CONFIG = {
    // Replace 'YOUR-RENDER-APP' with your actual Render app name
    // Example: 'https://pdfverse-api.onrender.com/api'
    API_URL: window.location.hostname === 'localhost' 
        ? 'http://localhost:5000/api'
        : 'https://YOUR-RENDER-APP.onrender.com/api'
};
