/** @type {import('next').NextConfig} */
// 存储管理台：独立应用 + 同域路径 + 网关按路径聚合（解耦审计 §7.3）。
// 冻结契约：basePath "/admin/storage"、容器内端口 3000、健康端点 /admin/storage/api/health。
// 网关（主仓库 deploy/nginx.conf）把 /admin/storage/ 反代到 storage-admin:3000，本应用的
// 数据请求仍旧走同域 /api/storage（由网关按域分流回存储服务），因此这里**不配 rewrites**：
// basePath 会连带前缀改写 rewrite 的 source，一条 "/api/:path*" 会盖掉本应用自己的
// app/api/health 路由——健康端点必须始终由本进程直接回答。
const nextConfig = {
  reactStrictMode: true,
  // 默认会带 X-Powered-By: Next.js（线上实测本管理台响应里就有），关掉它不改变任何行为。
  poweredByHeader: false,
  output: "standalone",
  basePath: "/admin/storage",
  // trailingSlash 必须为 true：网关给三条管理台路径各写了
  //   location = /admin/storage { return 301 /admin/storage/; }
  // （因为 /admin/storage 无尾斜杠会被最宽的 location / 兜给主前端，表现为 404）。
  // Next 默认（false）会把带尾斜杠的地址 308 回无尾斜杠形式，两者正好互相打回，
  // 浏览器看到的是"重定向次数过多"。让应用认领带尾斜杠这个规范形式，方向才与网关一致。
  trailingSlash: true,
  // 再关掉 Next 自己的尾斜杠归一化重定向：
  //   - 冻结契约的健康端点写作 /admin/storage/api/health（无尾斜杠），若应用把它 308 到带斜杠形式，
  //     运维/网关的探针就得依赖"跟随重定向"这一条隐含前提，契约里的字面路径反而不是 200；
  //   - 页面路径两种写法都能直接出内容，也就再没有"应用 308 → 网关 301"的回环可能。
  // 客户端跳转仍按 trailingSlash: true 生成带尾斜杠的规范地址。
  skipTrailingSlashRedirect: true,
  images: { unoptimized: true },
};

export default nextConfig;
