const colors = require("tailwindcss/colors");

module.exports = {
    theme: {
        colors: {
            midnight: "#17172F",
            twilight: "#1F1F3F",
            noon: "#E7E7FF",
            dapper: "#C00C0C",

            "discord-bg-dark": "#36393F",
            "discord-bg-light": "#FFFFFF",
            "discord-muted-dark": "#72767D",
            "discord-muted-light": "#747F8D",
            "discord-text-dark": "#DCDDDE",
            "discord-text-light": "#2E3338",
            "discord-link": "#00B0F4",
            "discord-embed-bg": "#2F3136",

            ...colors
        },
        fontFamily: {
            sans: ["Poppins", "sans-serif"],
            serif: ["Palatino Linotype", "serif"]
        }
    },
    darkMode: "media"
};