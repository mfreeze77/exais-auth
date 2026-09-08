import { build } from 'esbuild';
await build({ entryPoints: ['client.jsx'], bundle: true, outfile: 'public/app.js', minify: true,
  define: { 'process.env.NODE_ENV': '"production"' }, sourcemap: false });
