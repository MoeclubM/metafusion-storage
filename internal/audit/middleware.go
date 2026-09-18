package audit

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// detailKey 是请求上下文里存放变更摘要草稿的键（Describe 写、中间件读）。
const detailKey = "audit_detail"

// Options 是审计中间件的接线参数。
type Options struct {
	// Recorder 为 nil 时不落库（离线单测只挂路由、不接库时用）；X-Request-Id 仍会回写。
	Recorder *Recorder
	// Actions 是「方法 + 路由模板」→ 动作码注册表：**只有登记过的请求才写审计**。
	// 键与 gin 的 c.FullPath() 同形，例如 "PUT /api/storage/upload/stream/:assetId"。
	Actions map[string]string
	// Exempt 是“是写方法但刻意不审计”的路由 → 一句理由。中间件不读它：
	// 它是写路由覆盖守卫测试的输入（新增写路由必须要么登记动作码、要么在这里写明理由）。
	Exempt map[string]string
	// Actor 从请求上下文取操作者；为 nil 时按匿名处理。
	Actor func(*gin.Context) Actor
}

// Middleware 返回审计中间件：挂在**写路由之前**（本服务挂 /api/storage 组上）。
//
// 时序上有两处刻意安排：
//   - 路由模板、IP、UA、request_id 在 c.Next() 之前取；
//   - 但 Actor 回调在 c.Next() **之后**才调用：本服务的鉴权是路由级中间件（v.Required()），
//     组级审计中间件排在它前面，进请求时 Principal 还没写进上下文（取到的会永远是匿名）。
//     契约 §3 要求草稿在进入时构造，这里把“取操作者”挪到返回后，是同一份数据的正确取法。
//   - result / error_code / http_status 只能在请求处理完之后判定。
func Middleware(o Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := strings.TrimSpace(c.GetHeader("X-Request-Id"))
		if requestID == "" {
			requestID = uuid.NewString()
		}
		// 回写同名响应头：网关与应用日志用同一个 id 关联同一次操作（契约 §1）。
		c.Header("X-Request-Id", requestID)

		method := c.Request.Method
		route := c.FullPath()
		if route == "" {
			// 未匹配到模板（404 等）时回落原始路径：route 只在有模板时才有聚合价值。
			route = c.Request.URL.Path
		}
		action := ""
		if o.Actions != nil {
			action = o.Actions[method+" "+route]
		}

		ip := c.ClientIP()
		ua := truncate(strings.TrimSpace(c.GetHeader("User-Agent")), MaxUserAgentLen)

		var detail *Detail
		if action != "" {
			// 只有被审计的请求才建草稿：GET 与豁免路由不必为审计分配任何东西。
			detail = &Detail{}
			c.Set(detailKey, detail)
		}

		c.Next()

		if action == "" || o.Recorder == nil {
			return
		}

		actor := Actor{CredentialType: CredentialAnonymous}
		if o.Actor != nil {
			if got := o.Actor(c); got.CredentialType != "" || got.UserID != "" {
				actor = got
			}
		}

		status := c.Writer.Status()
		result := "success"
		errorCode := ""
		if status >= 400 {
			result = "failure"
			errorCode = strings.TrimSpace(c.GetString(ErrorCodeKey))
			if errorCode == "" {
				// 处理器没记错误码时回落状态码：有码总比空着强，但要能看出是回落值。
				errorCode = "http_" + strconv.Itoa(status)
			}
		}

		o.Recorder.Record(Entry{
			Service:        ServiceName,
			Action:         action,
			ActorUserID:    actor.UserID,
			ActorUsername:  actor.Username,
			CredentialType: actor.CredentialType,
			ActorIP:        ip,
			ActorUserAgent: ua,
			TargetType:     detail.TargetType,
			TargetID:       detail.TargetID,
			Changes:        detail.Changes,
			Result:         result,
			ErrorCode:      errorCode,
			RequestMethod:  method,
			Route:          route,
			HTTPStatus:     status,
			RequestID:      requestID,
		})
	}
}

// Describe 由处理器调用，补充被动对象与变更摘要；同一次请求可以调多次（后写的键覆盖同名键）。
func Describe(c *gin.Context, d Detail) {
	if c == nil {
		return
	}
	if d.TargetType == "" && d.TargetID == "" && len(d.Changes) == 0 {
		return
	}
	if v, ok := c.Get(detailKey); ok {
		if cur, ok := v.(*Detail); ok {
			if d.TargetType != "" {
				cur.TargetType = d.TargetType
			}
			if d.TargetID != "" {
				cur.TargetID = d.TargetID
			}
			if len(d.Changes) > 0 {
				if cur.Changes == nil {
					cur.Changes = make(map[string]any, len(d.Changes))
				}
				for k, val := range d.Changes {
					cur.Changes[k] = val
				}
			}
			return
		}
	}
	copy := d
	c.Set(detailKey, &copy)
}

// Fail 记录失败的稳定错误码：处理器写出错误响应时调用，中间件据此写 result=failure + error_code。
// 错误码必须与响应体的 error 字段一致（契约 §1）——所以调用点应紧挨着写响应的地方。
func Fail(c *gin.Context, code string) {
	if c == nil || strings.TrimSpace(code) == "" {
		return
	}
	c.Set(ErrorCodeKey, code)
}
