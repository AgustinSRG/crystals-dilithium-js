const path = require('path');
const webpack = require('webpack');

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
            buffer: require.resolve('buffer/'),
        },
    },
    module: {
        rules: [{ test: /\.ts$/, loader: "ts-loader" }]
    },
    plugins: [
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
        }),
    ],
}
