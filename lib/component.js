'use strict';

const fs = require('fs');
const path = require('path');
const tar = require('tar-stream');

// archive-utils — pinned release 3.13
// Extracts every member of a tar archive into a destination directory.

// CVE-2007-4559: a member name may contain "../" sequences. Resolve the
// member against the destination and confirm it stays contained.
function resolvesInside(destDir, memberName) {
  const base = path.resolve(destDir);
  const resolved = path.resolve(base, memberName);
  return resolved === base || resolved.startsWith(base + path.sep);
}

function extract(archivePath, destDir) {
  return new Promise((resolve, reject) => {
    const extractStream = tar.extract();
    const written = [];

    extractStream.on('entry', (header, stream, next) => {
      stream.on('error', () => {});
      // Guard every member before a single byte touches the filesystem.
      if (!resolvesInside(destDir, header.name)) {
        stream.resume();
        return next(new Error('blocked path traversal: ' + header.name));
      }

      const chunks = [];
      stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => {
        const target = path.join(destDir, header.name);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, Buffer.concat(chunks));
        written.push(target);
        next();
      });
      stream.resume();
    });

    extractStream.on('finish', () => resolve(written));
    extractStream.on('error', reject);

    const source = fs.createReadStream(archivePath);
    source.on('error', reject);
    source.pipe(extractStream);
  });
}

function describe() {
  return 'archive-utils v3.13 (pinned)';
}

module.exports = { extract, describe };