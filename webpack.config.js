const path = require('path');
module.exports = {
    mode: "production",
    entry: "./src/index.ts",
    output: {
        filename: "dilithium.js",
        path: path.resolve(__dirname, 'dist.webpack'),
        library: "DilithiumAlgorithm",
    },
    resolve: {
        extensions: [".webpack.js", ".web.js", ".ts", ".js"],
        fallback: {
            "crypto": false,
        },
    },
    module: {
        rules: [{ test: /\.ts$/, loader: "ts-loader" }]
    }
}
