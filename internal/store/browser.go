package store

import "context"

// ListAssets is an operator-only view. Callers must check moderation permission.
func (s *Store) ListAssets(ctx context.Context, status, name string, limit, offset int) ([]Asset, bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+assetCols+` FROM storage.assets
		WHERE ($1='' OR status=$1) AND ($2='' OR file_name ILIKE '%' || $2 || '%')
		ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, status, name, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// ListBindings is an operator-only inventory. Asset details still use the
// existing read and content endpoints so every preview is checked anew.
func (s *Store) ListBindings(ctx context.Context, limit, offset int) ([]FileBinding, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT b.id,b.asset_id,b.target_entity_id,b.target_kind,b.binding_role,b.created_by,b.created_at,
		a.id,a.sha256,a.size_bytes,a.declared_size,a.mime_type,a.file_name,a.object_key,a.status,a.multipart_upload_id,a.hash_verified,a.fail_reason,a.uploader_id,a.upload_expires_at,a.blocked,a.blocked_reason,a.blocked_at,a.created_at,a.completed_at,a.reclaim_token,a.reclaim_claimed_at
		FROM storage.bindings b JOIN storage.assets a ON a.id=b.asset_id
		ORDER BY b.created_at DESC, b.id DESC LIMIT $1 OFFSET $2`, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []FileBinding{}
	for rows.Next() {
		var f FileBinding
		if err := rows.Scan(&f.ID, &f.AssetID, &f.TargetEntityID, &f.TargetKind, &f.BindingRole, &f.CreatedBy, &f.CreatedAt,
			&f.Asset.ID, &f.Asset.SHA256, &f.Asset.SizeBytes, &f.Asset.DeclaredSize, &f.Asset.MimeType, &f.Asset.FileName, &f.Asset.ObjectKey,
			&f.Asset.Status, &f.Asset.MultipartUploadID, &f.Asset.HashVerified, &f.Asset.FailReason, &f.Asset.UploaderID, &f.Asset.UploadExpiresAt, &f.Asset.Blocked, &f.Asset.BlockedReason, &f.Asset.BlockedAt, &f.Asset.CreatedAt, &f.Asset.CompletedAt, &f.Asset.ReclaimToken, &f.Asset.ReclaimClaimedAt); err != nil {
			return nil, false, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}
