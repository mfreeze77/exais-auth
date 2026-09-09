FROM node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS original
WORKDIR /app
COPY --chmod=0644 public/index.html ./public/index.html
RUN --network=none node -e "const fs=require('node:fs'); const r={directory_mode:fs.statSync('/app/public').mode&511,file_mode:fs.statSync('/app/public/index.html').mode&511}; process.setgid(1000);process.setuid(1000);try{fs.readFileSync('/app/public/index.html');r.nonroot_read=true;}catch(e){r.nonroot_read=false;r.error=e.code;} fs.writeFileSync('/tmp/original.json',JSON.stringify(r));if(r.directory_mode!==420||r.nonroot_read||r.error!=='EACCES')process.exit(1);"
FROM node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS corrected
WORKDIR /app
RUN --network=none mkdir -m 0755 public
COPY --chmod=0644 public/index.html ./public/index.html
RUN --network=none node -e "const fs=require('node:fs'); const r={directory_mode:fs.statSync('/app/public').mode&511,file_mode:fs.statSync('/app/public/index.html').mode&511}; process.setgid(1000);process.setuid(1000);try{fs.readFileSync('/app/public/index.html');r.nonroot_read=true;}catch(e){r.nonroot_read=false;r.error=e.code;} fs.writeFileSync('/tmp/corrected.json',JSON.stringify(r));if(r.directory_mode!==493||r.file_mode!==420||!r.nonroot_read)process.exit(1);"
FROM scratch
COPY --from=original /tmp/original.json /original.json
COPY --from=corrected /tmp/corrected.json /corrected.json
