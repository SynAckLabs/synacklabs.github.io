// scripts/import-notion.mjs
import 'dotenv/config'; // Carga el .env automáticamente
import { Client } from '@notionhq/client';
import { NotionToMarkdown } from 'notion-to-md';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import slugify from 'slugify';
import { extraCategoriesFor } from './lib/series.mjs';

// --- CONFIGURACIÓN ---
const NOTION_TOKEN = process.env.NOTION_TOKEN;
const DATABASE_ID = process.env.NOTION_DATABASE_ID;
const CONTENT_DIR = 'content/posts';
const STATIC_IMG_DIR = 'static/images/notion';

// Inicializar cliente real
const notion = new Client({ auth: NOTION_TOKEN });
const n2m = new NotionToMarkdown({ notionClient: notion });

// Validar configuración
if (!NOTION_TOKEN || !DATABASE_ID) {
    console.error("❌ ERROR: Faltan las claves en el archivo .env");
    process.exit(1);
}

async function downloadImage(url, filename) {
  const filepath = path.join(STATIC_IMG_DIR, filename);
  const dir = path.dirname(filepath);
  
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const writer = fs.createWriteStream(filepath);
  const response = await axios({
    url,
    method: 'GET',
    responseType: 'stream'
  });

  response.data.pipe(writer);

  return new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('error', reject);
  });
}

n2m.setCustomTransformer('image', async (block) => {
  const { image } = block;
  const imageUrl = image.type === 'external' ? image.external.url : image.file.url;
  const caption = image.caption.length ? image.caption[0].plain_text : 'Imagen del post';
  const filename = `${block.id}.png`; 
  
  try {
    await downloadImage(imageUrl, filename);
    return `![${caption}](/images/notion/${filename})`;
  } catch (error) {
    return `![Error imagen](${imageUrl})`;
  }
});

n2m.setCustomTransformer('callout', async (block) => {
  const { callout } = block;
  const text = callout.rich_text.map(t => t.plain_text).join('');
  const icon = callout.icon.emoji || '💡';

  let type = 'info'; 
  if (callout.color === 'red_background') type = 'danger';
  if (callout.color === 'blue_background') type = 'note';
  if (callout.color === 'yellow_background') type = 'warning';

  return `
{{< alert type="${type}" >}}
**${icon} Nota:** ${text}
{{< /alert >}}
`;
});

// --- LÓGICA PRINCIPAL ---

async function getBlogPosts() {
  console.log('🔄 Conectando con Notion...');
  
  try {
      // The Notion SDK v5 changed the API. We need to use the REST API directly
      // or use the appropriate method. The databases object doesn't have a query method.
      // We'll use axios to make the request directly to the Notion API.
      
      const response = await axios.post(
        `https://api.notion.com/v1/databases/${DATABASE_ID}/query`,
        {
          filter: {
            property: 'Status',
            select: {
              equals: 'Publicado',
            },
          },
        },
        {
          headers: {
            'Authorization': `Bearer ${NOTION_TOKEN}`,
            'Notion-Version': '2022-06-28',
            'Content-Type': 'application/json',
          },
        }
      );

      console.log(`✅ Conexión exitosa. Encontrados ${response.data.results.length} artículos.`);

      for (const page of response.data.results) {
        const props = page.properties;
        
        // Validación segura de propiedades
        if (!props.Name || !props.Slug || !props.Date || !props.Author || !props.Tags) {
             console.warn(`⚠️ Saltando página "${page.id}" porque le faltan columnas obligatorias.`);
             continue;
        }

        const title = props.Name.title[0]?.plain_text || 'Sin titulo';
        const slug = props.Slug.rich_text[0]?.plain_text || slugify(title, { lower: true });
        const date = props.Date.date?.start || new Date().toISOString().split('T')[0];
        
        let author = [];
        if (props.Author.multi_select) {
            author = props.Author.multi_select.map(tag => tag.name);
        }

        // Manejo seguro de tags (si está vacío)
        let tags = [];
        if (props.Tags.multi_select) {
            tags = props.Tags.multi_select.map(tag => tag.name);
        }
        const postType = props.Type?.select?.name || "General";
        console.log(`📝 Procesando: ${title}`);

        const mdBlocks = await n2m.pageToMarkdown(page.id);
        // CAMBIO 1: Guardamos el markdown en una variable para editarlo
        let mdContent = n2m.toMarkdownString(mdBlocks).parent;

        // CAMBIO 2: Buscamos nuestra "marca" de Notion y la convertimos en el corte de Hugo
        // Si escribes "---more---" en Notion, aquí se convertirá en el botón de leer más
        if (mdContent.includes("---more---")) {
          mdContent = mdContent.replace("---more---", "");
        } else {
            // Opcional: Si se te olvida poner la marca, cortamos automático tras 300 caracteres
            // Descomenta la siguiente línea si quieres corte automático siempre:
            // mdContent = mdContent.substring(0, 300) + "...\n\n\n\n" + mdContent.substring(300);
        }

        const frontmatter = `---
title: "${title}"
date: ${date}
author: "${author}"
tags: [${tags.map(t => `"${t}"`).join(', ')}]
categories: [${[postType, ...extraCategoriesFor(slug)].map(c => `"${c}"`).join(", ")}]
slug: "${slug}"
draft: false
---

`;

        const fileName = `${slug}.md`;
        if (!fs.existsSync(CONTENT_DIR)) fs.mkdirSync(CONTENT_DIR, { recursive: true });
        
        // CAMBIO 3: Usamos nuestra variable 'mdContent' modificada
        fs.writeFileSync(path.join(CONTENT_DIR, fileName), frontmatter + mdContent);
      }
      
      console.log('🚀 ¡Todo listo! Ejecuta "hugo server" para ver los cambios.');
      
  } catch (error) {
      console.error("\n❌ ERROR DE CONEXIÓN:");
      console.error(error.message || error);
  }
}

getBlogPosts();