// 应用的固定契约（与主仓库 deploy/nginx.conf、deploy/docker-compose.yml 里的三条 location 一致）：
//   basePath "/admin/storage"、容器内端口 3000、健康端点 "/admin/storage/api/health"。
// next.config.mjs 里的 basePath 与这里必须同源，改一处就要改另一处——因此放在一个常量里，
// 供导航高亮（usePathname 返回的是**带前缀**的路径）等需要"减掉前缀"的地方使用。
export const BASE_PATH = "/admin/storage";
export const SERVICE_NAME = "storage-admin";
