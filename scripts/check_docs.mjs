import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { resolve, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../docs/.vitepress/dist')
const origin = 'https://rainchen537.github.io'
const base = '/dnsgo/'
const failures = []

function collect(directory) {
  return readdirSync(directory).flatMap(name => {
    const file = resolve(directory, name)
    return statSync(file).isDirectory() ? collect(file) : file.endsWith('.html') ? [file] : []
  })
}

if (!existsSync(resolve(root, 'index.html'))) {
  throw new Error('缺少文档构建产物，请先运行 vitepress build docs')
}

const pages = collect(root)
for (const file of pages) {
  const page = relative(root, file)
  const html = readFileSync(file, 'utf8')
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1])
  if (new Set(ids).size !== ids.length) failures.push(`${page}: 存在重复锚点`)
  for (const match of html.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
    const target = new URL(match[1].replaceAll('&amp;', '&'), `${origin}${base}${page}`)
    if (target.origin !== origin) continue
    if (!target.pathname.startsWith(base)) {
      failures.push(`${page}: 链接超出站点路径 ${target.pathname}`)
      continue
    }
    const pathname = decodeURIComponent(target.pathname.slice(base.length))
    let destination = resolve(root, pathname)
    if (existsSync(destination) && statSync(destination).isDirectory()) destination = resolve(destination, 'index.html')
    if (!existsSync(destination)) {
      failures.push(`${page}: 资源不存在 ${pathname}`)
      continue
    }
    if (target.hash && destination.endsWith('.html')) {
      const anchor = decodeURIComponent(target.hash.slice(1))
      if (!readFileSync(destination, 'utf8').includes(`id="${anchor}"`)) {
        failures.push(`${page}: 锚点不存在 ${pathname}#${anchor}`)
      }
    }
  }
}

if (failures.length) {
  console.error(failures.join('\n'))
  process.exitCode = 1
} else {
  console.log(`Wiki 产物检查通过，核对 ${pages.length} 个页面的链接、资源与锚点`)
}
