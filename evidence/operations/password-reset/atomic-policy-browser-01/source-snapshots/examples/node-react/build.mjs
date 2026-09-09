import { build } from 'esbuild';
await build({ entryPoints: ['client.jsx'], bundle: true, minify: true, outfile: 'public/app.js', define: { 'process.env.NODE_ENV': JSON.stringify('production') } });
