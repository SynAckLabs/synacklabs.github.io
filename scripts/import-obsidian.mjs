// scripts/import-obsidian.mjs
// Convierte los writeups de la carpeta "Blog" del vault de Obsidian en posts de Hugo.
//
// Uso:  npm run import:obsidian            (lee rutas de .env)
//       node scripts/import-obsidian.mjs --dry-run
//
// Variables (.env):
//   OBSIDIAN_BLOG_DIR         carpeta con los writeups listos para publicar
//   OBSIDIAN_ATTACHMENTS_DIR  carpeta de imágenes del vault (attachmentFolderPath)
import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import { extraCategoriesFor } from './lib/series.mjs';

const CONTENT_DIR = 'content/posts';
const STATIC_IMG_DIR = 'static/images/obsidian';
const PUBLIC_IMG_PREFIX = '/images/obsidian';
const SOURCE_MARKER = 'source: "obsidian"';

const BLOG_DIR = process.env.OBSIDIAN_BLOG_DIR;
const ATTACHMENTS_DIR = process.env.OBSIDIAN_ATTACHMENTS_DIR;
const DRY_RUN = process.argv.includes('--dry-run');

const CALLOUT_LABELS = {
  note: '📝 Nota', info: 'ℹ️ Info', tip: '💡 Tip', hint: '💡 Tip',
  important: '❗ Importante', warning: '⚠️ Aviso', caution: '⚠️ Aviso',
  danger: '🚨 Peligro', bug: '🐛 Bug', example: '🧪 Ejemplo', quote: '💬 Cita',
};

if (!BLOG_DIR || !ATTACHMENTS_DIR) {
  console.error('❌ Faltan OBSIDIAN_BLOG_DIR u OBSIDIAN_ATTACHMENTS_DIR en .env');
  process.exit(1);
}
for (const dir of [BLOG_DIR, ATTACHMENTS_DIR]) {
  if (!fs.existsSync(dir)) {
    console.error(`❌ No existe la carpeta: ${dir}`);
    process.exit(1);
  }
}

// --- utilidades ---

function listMarkdown(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listMarkdown(full);
    return entry.name.endsWith('.md') ? [full] : [];
  });
}

function splitFrontmatter(raw) {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return null;
  return { frontmatter: match[1], body: match[2] };
}

function readField(frontmatter, field) {
  const match = frontmatter.match(new RegExp(`^${field}:\\s*"?([^"\\n]*)"?\\s*$`, 'm'));
  return match ? match[1].trim() : null;
}

// Añade al campo `categories: [...]` las categorías de data/*.json (sin duplicar)
function withSeriesCategories(frontmatter, slug) {
  const extra = extraCategoriesFor(slug);
  if (!extra.length) return frontmatter;

  const match = frontmatter.match(/^categories:\s*\[(.*)\]\s*$/m);
  const current = match ? [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
  const merged = [...new Set([...current, ...extra])].map((c) => `"${c}"`).join(', ');
  const line = `categories: [${merged}]`;
  return match ? frontmatter.replace(match[0], line) : `${frontmatter.trim()}\n${line}`;
}

function safeFileName(name) {
  return name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/-+/g, '-');
}

// Aplica `transform` solo a las líneas fuera de bloques de código ``` / ~~~
function mapOutsideCode(body, transform) {
  let inFence = false;
  return body.split('\n').map((line) => {
    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      return line;
    }
    return inFence ? line : transform(line);
  }).join('\n');
}

// --- transformaciones Obsidian -> Hugo ---

function convertImages(line, slug, images) {
  return line.replace(/!\[\[([^\]|]+?)(?:\|[^\]]*)?\]\]/g, (_, target) => {
    const original = path.basename(target.trim());
    const published = safeFileName(original);
    images.push({ original, published });
    return `![${slug}](${PUBLIC_IMG_PREFIX}/${slug}/${published})`;
  });
}

function convertWikilinks(line) {
  return line.replace(/(?<!!)\[\[([^\]|]+?)(?:\|([^\]]+))?\]\]/g, (_, target, alias) => alias || target.split('#')[0]);
}

function convertCallouts(line) {
  return line.replace(/^(\s*>\s*)\[!(\w+)\][+-]?\s*(.*)$/, (_, prefix, type, title) => {
    const label = CALLOUT_LABELS[type.toLowerCase()] || '📝 Nota';
    return `${prefix}**${title || label}**`;
  });
}

function convertBody(body, slug) {
  const images = [];
  const converted = mapOutsideCode(body, (line) =>
    convertCallouts(convertWikilinks(convertImages(line, slug, images))));
  return { markdown: converted, images };
}

// --- E/S ---

function copyImages(slug, images) {
  const missing = images.filter(({ original }) => !fs.existsSync(path.join(ATTACHMENTS_DIR, original)));
  if (DRY_RUN) return missing;

  const targetDir = path.join(STATIC_IMG_DIR, slug);
  fs.mkdirSync(targetDir, { recursive: true });
  images
    .filter((img) => !missing.includes(img))
    .forEach(({ original, published }) =>
      fs.copyFileSync(path.join(ATTACHMENTS_DIR, original), path.join(targetDir, published)));
  return missing;
}

function isForeignPost(targetFile) {
  return fs.existsSync(targetFile) && !fs.readFileSync(targetFile, 'utf8').includes(SOURCE_MARKER);
}

function processFile(file) {
  const name = path.basename(file);
  const parts = splitFrontmatter(fs.readFileSync(file, 'utf8'));
  if (!parts) return { name, error: 'sin frontmatter' };

  const slug = readField(parts.frontmatter, 'slug');
  if (!slug) return { name, error: 'falta "slug" en el frontmatter' };
  if (readField(parts.frontmatter, 'draft') === 'true') return { name, skipped: 'draft: true' };

  const targetFile = path.join(CONTENT_DIR, `${slug}.md`);
  if (isForeignPost(targetFile)) return { name, error: `el slug "${slug}" ya lo usa un post de Notion` };

  const { markdown, images } = convertBody(parts.body, slug);
  const missing = copyImages(slug, images);
  if (missing.length) {
    return { name, error: `imágenes no encontradas: ${missing.map((m) => m.original).join(', ')}` };
  }

  const frontmatter = withSeriesCategories(parts.frontmatter, slug).trim();
  const output = `---\n${frontmatter}\n${SOURCE_MARKER}\n---\n\n${markdown.trim()}\n`;
  if (!DRY_RUN) {
    fs.mkdirSync(CONTENT_DIR, { recursive: true });
    fs.writeFileSync(targetFile, output);
  }
  return { name, slug, images: images.length };
}

function main() {
  const files = listMarkdown(BLOG_DIR);
  console.log(`🔄 ${files.length} writeups en ${BLOG_DIR}${DRY_RUN ? ' (dry-run)' : ''}`);

  const results = files.map(processFile);
  results.forEach((r) => {
    if (r.error) console.error(`❌ ${r.name}: ${r.error}`);
    else if (r.skipped) console.log(`⏭️  ${r.name}: ${r.skipped}`);
    else console.log(`✅ ${r.name} -> ${CONTENT_DIR}/${r.slug}.md (${r.images} imágenes)`);
  });

  const failed = results.filter((r) => r.error).length;
  if (failed) {
    console.error(`\n${failed} writeup(s) con errores.`);
    process.exit(1);
  }
  console.log('\n🚀 Listo. Revisa con "hugo server" y haz commit + push para publicar.');
}

main();
