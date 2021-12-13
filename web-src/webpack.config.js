const {VueLoaderPlugin} = require("vue-loader");
const HtmlPlugin = require("html-webpack-plugin");
const PreloadPlugin = require("@vue/preload-webpack-plugin");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const {HotModuleReplacementPlugin} = require("webpack");

const path = require("path");
const purgecss = require("@fullhuman/postcss-purgecss");
const glob = require("glob");

const favicon = glob.sync("src/favicon.*").sort((a, b) => (a < b) - (a > b))[0] || null;
// The above is a convenient way to prioritize images by web-ready-ness. WEBP > PNG > JPG > ICO

module.exports = (env, argv) => ({
    entry: "./src/main.js",

    devServer: {
        compress: true,
        progress: true,
        hot: true,
        https: true,
        open: true,
        port: 8443,
        stats: {
            all: false,

            errors: true,
            warnings: true,
            errorsCount: true,
            warningsCount: true,
            errorStack: true,

            hash: true,
            log: "warn",
            builtAt: true
        }
    },

    output: {
        path: path.resolve("../web"),
        clean: true,

        filename: "[name].[contenthash].js",
        chunkFilename: "[id].[contenthash].js",
        assetModuleFilename: "[name].[contenthash][ext]",

        hashDigestLength: 12,
        hashFunction: "sha256"
    },

    devtool: argv.mode === "production" ? false : "eval-cheap-module-source-map",

    module: {
        rules: [
            {
                test: /\.vue$/i,
                loader: "vue-loader"
            },
            {
                test: /\.css$/i,
                use: [
                    "vue-style-loader",
                    argv.mode === "production" ? MiniCssExtractPlugin.loader : "style-loader",
                    "css-loader",
                    {
                        loader: "postcss-loader",
                        options: {
                            postcssOptions: {
                                plugins: [
                                    "tailwindcss",
                                    "autoprefixer"
                                ].concat(argv.mode === "production" ? [
                                    purgecss({
                                        content: [
                                            "./src/**/*.html",
                                            "./src/**/*.vue",
                                            "./src/**/*.js"
                                        ],
                                        css: [
                                            "./src/**/*.css"
                                        ],
                                        variables: true,
                                        defaultExtractor:
                                            content => content.match(/[A-Za-z0-9\-:\/]+/g)
                                    }),
                                    "cssnano"
                                ] : [])
                            }
                        }
                    }
                ]
            },
            {
                test: /\.(?:png|gif|ico|jpe?g|webp|avif|svg|mp4|webm|mkv)$/i,
                type: "asset",
                parser: {
                    dataUrlCondition: {
                        maxSize: 4096
                    }
                }
            }
        ].concat(argv.mode === "production" ? [
            {
                test: /\.[mc]?[jt]sx?$/i,
                exclude: /node_modules/,
                use: {
                    loader: "babel-loader",
                    options: {
                        presets: [
                            ["@babel/preset-env", {useBuiltIns: "entry", corejs: 3}]
                        ],
                        plugins: [
                            "@babel/plugin-syntax-dynamic-import"
                        ]
                    }
                }
            }
        ] : [])
    },
    plugins: glob.sync("src/**/index.html").map(f =>
        new HtmlPlugin(Object.assign({
            template: f,
            filename: f.split("/").slice(1).join("/"),
            meta: {
                referrer: "no-referrer",
                keywords: "sharex, image host, dapper, uploader, files, sxcu, pomf",
                author: require("./package.json").author,
                viewport: "width=device-width, initial-scale=1, shrink-to-fit=no",
                "theme-color": {
                    property: "theme-color",
                    content: "#C00C0C"
                },
                charset: {
                    charset: "UTF-8"
                }
            },
            hash: false,
            minify: argv.mode === "production" ? {
                removeAttributeQuotes: true,
                removeComments: true,
                useShortDoctype: true,
                removeRedundantAttributes: true,
                removeScriptTypeAttributes: true,
                removeStyleLinkTypeAttributes: true,
                collapseWhitespace: true,
                conservativeCollapse: true
            } : false,
            templateParameters: {
                titlePrefix: "DIH &bull;"
            }
        }, favicon === null ? {} : {favicon}))
    ).concat([
        new VueLoaderPlugin()
    ]).concat(argv.mode === "production" ? [
        new PreloadPlugin(),
        new MiniCssExtractPlugin({
            filename: "[name].[contenthash].css"
        })
    ] : [
        new HotModuleReplacementPlugin()
    ]),

    optimization: {
        minimize: argv.mode === "production",

        moduleIds: "deterministic",
        chunkIds: "deterministic",
        splitChunks: {
            chunks: argv.mode === "production" ? "all" : "async"
        }
    }
});