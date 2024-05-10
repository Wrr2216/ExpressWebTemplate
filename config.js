module.exports = {
    copyrightText: "© 2024 Miller Cyber Technologies. All rights reserved.",
    copyrightSite: "https://millercybertech.com",
    database: { // MySQL Database Configuration
        host: 'localhost',
        user: 'your_database_user',
        password: 'your_database_password',
        database: 'your_database_name'
    },
    siteTitle: "Miller Cyber Technologies", // Website Title
    siteDescription: "Your description here", // Website Description
    siteKeywords: "Your, Keywords, Here", // Website Keywords
    siteAuthor: "Your Name", // Website Author
    siteEmail: "l.miller@millercybertech.com", // Website Email
    siteColors: { // Site Styles
        primary: "#007bff",
        secondary: "#6c757d",
        success: "#28a745",
        danger: "#dc3545",
        warning: "#ffc107",
        info: "#17a2b8",
        light: "#f8f9fa",
        dark: "#343a40"
    },
    favicon: "public/images/favicon.ico", // Website Favicon
    serverPort: 3000, // Server Port
    logLevel: "dev", // Dev - Development, Prod - Production
    sessionSecret: "your_secret_key", // Session Secret
    sessionName: "your_session_name", // Session Name
    buildVersion: "1.0.0", // Build Version
};