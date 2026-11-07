// Categorías extra según el slug (p. ej. máquinas del track "CPTS Preparation").
// Fuente única: data/cpts.json, usada por import-notion.mjs e import-obsidian.mjs.
import fs from 'fs';

const SERIES_FILES = ['data/cpts.json'];

const series = SERIES_FILES
  .filter((file) => fs.existsSync(file))
  .map((file) => JSON.parse(fs.readFileSync(file, 'utf8')));

export function extraCategoriesFor(slug) {
  const clean = String(slug).replace(/^\/+|\/+$/g, '').toLowerCase(); // Notion guarda "/giveback"
  return series.filter((s) => s.slugs.includes(clean)).map((s) => s.category);
}
