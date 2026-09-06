package models

import (
    "time"
    "github.com/google/uuid"
)

type AssetFile struct {
    ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
    SHA256       string    `gorm:"size:64;uniqueIndex;not null" json:"sha256"`
    ED2K         string    `gorm:"size:32;index" json:"ed2k,omitempty"`
    SizeBytes    int64     `gorm:"not null" json:"size_bytes"`
    MimeType     string    `gorm:"size:128;not null" json:"mime_type"`
    StorageURI   string    `gorm:"type:text;not null" json:"storage_uri"`
    StorageTier  string    `gorm:"size:32;default:hot" json:"storage_tier"`
    CreatedAt    time.Time `json:"created_at"`
}

type FileBinding struct {
    ID             uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
    FileID         uuid.UUID `gorm:"type:uuid;index;not null" json:"file_id"`
    TargetEntityID uuid.UUID `gorm:"type:uuid;index;not null" json:"target_entity_id"`
    TargetKind     string    `gorm:"size:32;not null" json:"target_kind"`
    FileName       string    `gorm:"size:255;not null" json:"file_name"`
    DownloadCount  int64     `gorm:"default:0" json:"download_count"`
    CreatedAt      time.Time `json:"created_at"`
}
