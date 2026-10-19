import { dirname, resolve, relative } from 'node:path'
import { execFileSync } from 'node:child_process'
import { cpSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitepress'

const repository = 'https://github.com/Rainchen537/dnsgo'
const root = fileURLToPath(new URL('../..', import.meta.url))
const base = '/dnsgo/'
const upstreamCommit = execFileSync('git', ['ls-tree', 'HEAD', 'reference/dnsmgr'], { cwd: root, encoding: 'utf8' }).split(/\s+/)[2]

export default defineConfig({
  lang: 'zh-CN',
  title: 'DnsGo',
  description: 'DnsGo Go DNS SDK 项目 Wiki',
  base,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#2563eb' }],
  ],
  sitemap: { hostname: 'https://rainchen537.github.io/dnsgo/' },
  buildEnd(config) {
    cpSync(resolve(root, 'docs/verification'), resolve(config.outDir, 'verification'), { recursive: true })
  },
  vite: {
    plugins: [{
      name: 'dnsgo-local-search-hmr',
      enforce: 'pre',
      resolveId(id) {
        if (id.startsWith('/@localSearchIndex')) return id
      },
    }],
  },
  themeConfig: {
    logo: { src: '/favicon.svg', alt: 'DnsGo' },
    siteTitle: 'DnsGo Wiki',
    nav: [
      { text: '接入', link: '/QUICKSTART' },
      { text: '参考', link: '/CONFIG-KEYS' },
      { text: '验证', link: '/ADAPTER-COVERAGE' },
      { text: '发布', link: `${repository}/releases` },
    ],
    sidebar: [
      {
        text: '使用',
        items: [
          { text: '快速开始', link: '/QUICKSTART' },
          { text: '项目概览', link: '/overview' },
          { text: 'Go SDK 接入', link: '/SDK' },
          { text: 'DNS 操作', link: '/DNS-OPERATIONS' },
          { text: '证书与部署', link: '/CERTIFICATES' },
          { text: '自动化与通知', link: '/AUTOMATION' },
          { text: '常驻程序', link: '/AGENT' },
          { text: '故障排查', link: '/TROUBLESHOOTING' },
        ],
      },
      {
        text: '参考',
        items: [
          { text: '配置字段', link: '/CONFIG-KEYS' },
          { text: '上游源码盘点', link: '/UPSTREAM-INVENTORY' },
          { text: '品牌素材', link: '/BRAND' },
        ],
      },
      {
        text: '项目维护',
        items: [
          { text: '适配器验证', link: '/ADAPTER-COVERAGE' },
          { text: '实施状态', link: '/IMPLEMENTATION' },
          { text: '开发与发布', link: '/CONTRIBUTING' },
          { text: 'Wiki 维护', link: '/WIKI' },
          { text: '第三方来源与署名', link: '/third-party' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: repository }],
    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
              modal: {
                displayDetails: '显示详情',
                resetButtonTitle: '清除搜索',
                backButtonTitle: '返回',
                noResultsText: '未找到相关文档',
                footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' },
              },
            },
          },
        },
      },
    },
    outline: { label: '本页目录', level: [2, 3] },
    docFooter: { prev: '上一篇', next: '下一篇' },
    darkModeSwitchLabel: '主题',
    lightModeSwitchTitle: '切换浅色主题',
    darkModeSwitchTitle: '切换深色主题',
    sidebarMenuLabel: '文档目录',
    returnToTopLabel: '返回顶部',
    skipToContentLabel: '跳转到内容',
    lastUpdated: { text: '更新于', formatOptions: { dateStyle: 'medium' } },
    editLink: {
      pattern: ({ relativePath }) => {
        const source = relativePath === 'overview.md' ? 'README.md'
          : relativePath === 'third-party.md' ? 'THIRD_PARTY_NOTICES.md'
            : `docs/${relativePath}`
        return `https://github.com/Rainchen537/dnsgo/edit/main/${source}`
      },
      text: '在 GitHub 上编辑此页',
    },
    footer: { message: 'MIT License', copyright: 'DnsGo' },
  },
  markdown: {
    config(markdown) {
      const renderLink = markdown.renderer.rules.link_open
      markdown.renderer.rules.link_open = (tokens, index, options, env, renderer) => {
        const token = tokens[index]
        const href = token.attrGet('href')
        const link = href && !/^[a-z][\w+.-]*:/i.test(href) ? href.replace(/#(?=\d)/, '#_') : href
        if (link !== href) token.attrSet('href', link)
        if (link && !/^(?:[a-z][\w+.-]*:|\/|#)/i.test(link)) {
          const [pathname, fragment] = link.split('#', 2)
          const fromRoot = env.relativePath === 'overview.md' || env.relativePath === 'third-party.md'
          const source = relative(root, resolve(fromRoot ? root : dirname(env.path), pathname))
          const anchor = fragment ? `#${fragment}` : ''
          if (source === 'README.md' || source === 'THIRD_PARTY_NOTICES.md') {
            token.attrSet('href', `/${source === 'README.md' ? 'overview' : 'third-party'}.md${anchor}`)
          } else if (source.startsWith('reference/dnsmgr/')) {
            token.attrSet('href', `https://github.com/netcccyun/dnsmgr/blob/${upstreamCommit}/${source.slice(17)}${anchor}`)
          } else if (!source.startsWith('docs/')) {
            token.attrSet('href', `${repository}/blob/main/${source}${anchor}`)
          } else if (fromRoot) {
            token.attrSet('href', `/${source.slice(5)}${anchor}`)
          }
        }
        return renderLink ? renderLink(tokens, index, options, env, renderer)
          : renderer.renderToken(tokens, index, options)
      }
    },
  },
})
