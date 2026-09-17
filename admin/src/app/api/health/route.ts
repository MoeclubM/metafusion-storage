import { NextResponse } from "next/server";

// 冻结契约的健康端点：GET /admin/storage/api/health（basePath 由 Next 自动带上前缀）。
// 刻意不引入任何依赖：网关与运维就是拿它判断"这个管理台进程在不在答话"，
// 让它去探测存储服务或登录态，会把"管理台活着但上游挂了"说成"管理台挂了"。
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ ok: true, service: "storage-admin" });
}
