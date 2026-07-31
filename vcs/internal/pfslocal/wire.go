package pfslocal

import (
	"errors"
	"fmt"
)

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

var ErrMalformed = errors.New("pfslocal: malformed protobuf")

func MarshalEnvelope(e *Envelope) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("pfslocal: nil envelope")
	}
	var b []byte
	b = appendU64(b, 1, e.RequestID)
	b = appendBool(b, 2, e.PublicationAckRequired)
	b = appendU64(b, 3, e.OperationID)
	if e.Body == nil {
		return b, nil
	}
	num, payload, err := marshalBody(e.Body)
	if err != nil {
		return nil, err
	}
	b = appendMsg(b, num, payload)
	return b, nil
}

func UnmarshalEnvelope(b []byte) (*Envelope, error) {
	e := &Envelope{}
	for len(b) > 0 {
		num, wt, rest, err := consumeTag(b)
		if err != nil {
			return nil, err
		}
		b = rest
		switch num {
		case 1:
			if wt != wireVarint {
				return nil, ErrMalformed
			}
			var v uint64
			v, b, err = consumeVarint(b)
			if err != nil {
				return nil, err
			}
			e.RequestID = v
		case 2:
			if wt != wireVarint {
				return nil, ErrMalformed
			}
			var v uint64
			v, b, err = consumeVarint(b)
			if err != nil {
				return nil, err
			}
			e.PublicationAckRequired = v != 0
		case 3:
			if wt != wireVarint {
				return nil, ErrMalformed
			}
			var v uint64
			v, b, err = consumeVarint(b)
			if err != nil {
				return nil, err
			}
			e.OperationID = v
		case 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
			60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 90, 91:
			if wt != wireBytes {
				return nil, ErrMalformed
			}
			var payload []byte
			payload, b, err = consumeBytes(b)
			if err != nil {
				return nil, err
			}
			body, err := unmarshalBody(num, payload)
			if err != nil {
				return nil, err
			}
			e.Body = body
		default:
			b, err = skipValue(wt, b)
			if err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}

func marshalBody(v any) (int, []byte, error) {
	switch m := v.(type) {
	case *Hello:
		return 10, marshalHello(m), nil
	case *ResolveRequest:
		return 11, marshalResolveRequest(m), nil
	case *LookupRequest:
		return 12, marshalLookupRequest(m), nil
	case *EnumerateRequest:
		return 13, marshalEnumerateRequest(m), nil
	case *GetAttrRequest:
		return 14, marshalGetAttrRequest(m), nil
	case *SetAttrRequest:
		return 15, marshalSetAttrRequest(m), nil
	case *OpenRequest:
		return 16, marshalOpenRequest(m), nil
	case *CloseRequest:
		return 17, marshalCloseRequest(m), nil
	case *ReadRequest:
		return 18, marshalReadRequest(m), nil
	case *WriteRequest:
		return 19, marshalWriteRequest(m), nil
	case *CreateRequest:
		return 20, marshalCreateRequest(m), nil
	case *MkdirRequest:
		return 21, marshalMkdirRequest(m), nil
	case *RemoveRequest:
		return 22, marshalRemoveRequest(m), nil
	case *RenameRequest:
		return 23, marshalRenameRequest(m), nil
	case *SymlinkRequest:
		return 24, marshalSymlinkRequest(m), nil
	case *ReadlinkRequest:
		return 25, marshalReadlinkRequest(m), nil
	case *XattrGetRequest:
		return 26, marshalXattrGetRequest(m), nil
	case *XattrSetRequest:
		return 27, marshalXattrSetRequest(m), nil
	case *XattrListRequest:
		return 28, marshalXattrListRequest(m), nil
	case *XattrRemoveRequest:
		return 29, marshalXattrRemoveRequest(m), nil
	case *StatfsRequest:
		return 30, nil, nil
	case *FsyncRequest:
		return 31, marshalFsyncRequest(m), nil
	case *ReclaimRequest:
		return 32, marshalReclaimRequest(m), nil
	case *SubscribeEventsRequest:
		return 33, nil, nil
	case *HardLinkRequest:
		return 34, marshalHardLinkRequest(m), nil
	case *SyncVolumeRequest:
		return 35, nil, nil
	case *PublicationAck:
		return 36, marshalPublicationAck(m), nil
	case *HelloReply:
		return 60, marshalHelloReply(m), nil
	case *ResolveReply:
		return 61, marshalResolveReply(m), nil
	case *LookupReply:
		return 62, marshalLookupReply(m), nil
	case *EnumerateReply:
		return 63, marshalEnumerateReply(m), nil
	case *GetAttrReply:
		return 64, marshalGetAttrReply(m), nil
	case *SetAttrReply:
		return 65, marshalSetAttrReply(m), nil
	case *OpenReply:
		return 66, marshalOpenReply(m), nil
	case *CloseReply:
		return 67, marshalCloseReply(m), nil
	case *ReadReply:
		return 68, marshalReadReply(m), nil
	case *WriteReply:
		return 69, marshalWriteReply(m), nil
	case *CreateReply:
		return 70, marshalCreateReply(m), nil
	case *MkdirReply:
		return 71, marshalMkdirReply(m), nil
	case *RemoveReply:
		return 72, nil, nil
	case *RenameReply:
		return 73, nil, nil
	case *SymlinkReply:
		return 74, marshalSymlinkReply(m), nil
	case *ReadlinkReply:
		return 75, marshalReadlinkReply(m), nil
	case *XattrGetReply:
		return 76, marshalXattrGetReply(m), nil
	case *XattrSetReply:
		return 77, nil, nil
	case *XattrListReply:
		return 78, marshalXattrListReply(m), nil
	case *XattrRemoveReply:
		return 79, nil, nil
	case *StatfsReply:
		return 80, marshalStatfsReply(m), nil
	case *FsyncReply:
		return 81, nil, nil
	case *ReclaimReply:
		return 82, nil, nil
	case *SubscribeEventsReply:
		return 83, nil, nil
	case *HardLinkReply:
		return 84, marshalHardLinkReply(m), nil
	case *SyncVolumeReply:
		return 85, marshalSyncVolumeReply(m), nil
	case *ErrorReply:
		return 90, marshalErrorReply(m), nil
	case *Event:
		return 91, marshalEvent(m), nil
	default:
		return 0, nil, fmt.Errorf("pfslocal: unsupported body %T", v)
	}
}

func unmarshalBody(num int, b []byte) (any, error) {
	switch num {
	case 10:
		return unmarshalHello(b)
	case 11:
		return unmarshalResolveRequest(b)
	case 12:
		return unmarshalLookupRequest(b)
	case 13:
		return unmarshalEnumerateRequest(b)
	case 14:
		return unmarshalGetAttrRequest(b)
	case 15:
		return unmarshalSetAttrRequest(b)
	case 16:
		return unmarshalOpenRequest(b)
	case 17:
		return unmarshalCloseRequest(b)
	case 18:
		return unmarshalReadRequest(b)
	case 19:
		return unmarshalWriteRequest(b)
	case 20:
		return unmarshalCreateRequest(b)
	case 21:
		return unmarshalMkdirRequest(b)
	case 22:
		return unmarshalRemoveRequest(b)
	case 23:
		return unmarshalRenameRequest(b)
	case 24:
		return unmarshalSymlinkRequest(b)
	case 25:
		return unmarshalReadlinkRequest(b)
	case 26:
		return unmarshalXattrGetRequest(b)
	case 27:
		return unmarshalXattrSetRequest(b)
	case 28:
		return unmarshalXattrListRequest(b)
	case 29:
		return unmarshalXattrRemoveRequest(b)
	case 30:
		return &StatfsRequest{}, nil
	case 31:
		return unmarshalFsyncRequest(b)
	case 32:
		return unmarshalReclaimRequest(b)
	case 33:
		return &SubscribeEventsRequest{}, nil
	case 34:
		return unmarshalHardLinkRequest(b)
	case 35:
		return &SyncVolumeRequest{}, nil
	case 36:
		return unmarshalPublicationAck(b)
	case 60:
		return unmarshalHelloReply(b)
	case 61:
		return unmarshalResolveReply(b)
	case 62:
		return unmarshalLookupReply(b)
	case 63:
		return unmarshalEnumerateReply(b)
	case 64:
		return unmarshalGetAttrReply(b)
	case 65:
		return unmarshalSetAttrReply(b)
	case 66:
		return unmarshalOpenReply(b)
	case 67:
		return unmarshalCloseReply(b)
	case 68:
		return unmarshalReadReply(b)
	case 69:
		return unmarshalWriteReply(b)
	case 70:
		return unmarshalCreateReply(b)
	case 71:
		return unmarshalMkdirReply(b)
	case 72:
		return &RemoveReply{}, nil
	case 73:
		return &RenameReply{}, nil
	case 74:
		return unmarshalSymlinkReply(b)
	case 75:
		return unmarshalReadlinkReply(b)
	case 76:
		return unmarshalXattrGetReply(b)
	case 77:
		return &XattrSetReply{}, nil
	case 78:
		return unmarshalXattrListReply(b)
	case 79:
		return &XattrRemoveReply{}, nil
	case 80:
		return unmarshalStatfsReply(b)
	case 81:
		return &FsyncReply{}, nil
	case 82:
		return &ReclaimReply{}, nil
	case 83:
		return &SubscribeEventsReply{}, nil
	case 84:
		return unmarshalHardLinkReply(b)
	case 85:
		return unmarshalSyncVolumeReply(b)
	case 90:
		return unmarshalErrorReply(b)
	case 91:
		return unmarshalEvent(b)
	default:
		return nil, fmt.Errorf("pfslocal: unsupported oneof field %d", num)
	}
}

func marshalHello(m *Hello) []byte {
	var b []byte
	b = appendU32(b, 1, m.ProtocolMajor)
	b = appendU32(b, 2, m.ProtocolMinor)
	b = appendString(b, 3, m.ClientName)
	b = appendString(b, 4, m.ClientVersion)
	return b
}

func unmarshalHello(b []byte) (*Hello, error) {
	m := &Hello{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.ProtocolMajor = uint32(v)
			return err
		case 2:
			v, err := scalarU64(wt, raw)
			m.ProtocolMinor = uint32(v)
			return err
		case 3:
			v, err := scalarBytes(wt, raw)
			m.ClientName = string(v)
			return err
		case 4:
			v, err := scalarBytes(wt, raw)
			m.ClientVersion = string(v)
			return err
		}
		return nil
	})
}

func marshalHelloReply(m *HelloReply) []byte {
	var b []byte
	b = appendU32(b, 1, m.ProtocolMajor)
	b = appendU32(b, 2, m.ProtocolMinor)
	b = appendString(b, 3, m.DaemonVersion)
	return b
}

func unmarshalHelloReply(b []byte) (*HelloReply, error) {
	m := &HelloReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.ProtocolMajor = uint32(v)
			return err
		case 2:
			v, err := scalarU64(wt, raw)
			m.ProtocolMinor = uint32(v)
			return err
		case 3:
			v, err := scalarBytes(wt, raw)
			m.DaemonVersion = string(v)
			return err
		}
		return nil
	})
}

func marshalPublicationAck(m *PublicationAck) []byte {
	var b []byte
	b = appendU64(b, 1, m.PublishedRequestID)
	return appendU64(b, 2, m.OperationID)
}

func unmarshalPublicationAck(b []byte) (*PublicationAck, error) {
	m := &PublicationAck{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.PublishedRequestID = v
			return err
		case 2:
			v, err := scalarU64(wt, raw)
			m.OperationID = v
			return err
		}
		return nil
	})
}

func marshalResolveRequest(m *ResolveRequest) []byte {
	var b []byte
	return appendString(b, 1, m.AttachRef)
}

func unmarshalResolveRequest(b []byte) (*ResolveRequest, error) {
	m := &ResolveRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarBytes(wt, raw)
			m.AttachRef = string(v)
			return err
		}
		return nil
	})
}

func marshalResolveReply(m *ResolveReply) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Root))
	b = appendMsg(b, 2, marshalAttr(&m.RootAttr))
	b = appendString(b, 3, m.VolumeID)
	b = appendString(b, 4, m.Branch)
	b = appendString(b, 5, m.VolumeName)
	b = appendMsg(b, 6, marshalCapabilities(&m.Capabilities))
	return b
}

func unmarshalResolveReply(b []byte) (*ResolveReply, error) {
	m := &ResolveReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Root, err = parseItemField(wt, raw)
		case 2:
			m.RootAttr, err = parseAttrField(wt, raw)
		case 3:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.VolumeID = string(v)
		case 4:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.Branch = string(v)
		case 5:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.VolumeName = string(v)
		case 6:
			m.Capabilities, err = parseCapabilitiesField(wt, raw)
		}
		return err
	})
}

func marshalCapabilities(m *Capabilities) []byte {
	var b []byte
	b = appendBool(b, 1, m.Symlinks)
	b = appendBool(b, 2, m.HardLinks)
	b = appendBool(b, 3, m.Xattrs)
	b = appendBool(b, 4, m.CaseSensitive)
	b = appendU32(b, 5, m.MaxNameBytes)
	b = appendU64(b, 6, m.MaxFileSize)
	b = appendU32(b, 7, m.PreferredIOSize)
	return b
}

func parseCapabilitiesField(wt int, raw []byte) (Capabilities, error) {
	if wt != wireBytes {
		return Capabilities{}, ErrMalformed
	}
	m := Capabilities{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarBool(wt, raw)
			m.Symlinks = v
			return err
		case 2:
			v, err := scalarBool(wt, raw)
			m.HardLinks = v
			return err
		case 3:
			v, err := scalarBool(wt, raw)
			m.Xattrs = v
			return err
		case 4:
			v, err := scalarBool(wt, raw)
			m.CaseSensitive = v
			return err
		case 5:
			v, err := scalarU64(wt, raw)
			m.MaxNameBytes = uint32(v)
			return err
		case 6:
			v, err := scalarU64(wt, raw)
			m.MaxFileSize = v
			return err
		case 7:
			v, err := scalarU64(wt, raw)
			m.PreferredIOSize = uint32(v)
			return err
		}
		return nil
	})
}

func marshalItem(m *Item) []byte {
	var b []byte
	b = appendU64(b, 1, m.ItemID)
	b = appendU64(b, 2, m.ItemGeneration)
	return b
}

func parseItemField(wt int, raw []byte) (Item, error) {
	if wt != wireBytes {
		return Item{}, ErrMalformed
	}
	m := Item{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.ItemID = v
			return err
		case 2:
			v, err := scalarU64(wt, raw)
			m.ItemGeneration = v
			return err
		}
		return nil
	})
}

func marshalAttr(m *Attr) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendI32(b, 2, int32(m.Kind))
	b = appendU32(b, 3, m.Mode)
	b = appendU32(b, 4, m.Nlink)
	b = appendU32(b, 5, m.UID)
	b = appendU32(b, 6, m.GID)
	b = appendU64(b, 7, m.Size)
	b = appendI64(b, 8, m.MtimeMs)
	b = appendI64(b, 9, m.CtimeMs)
	b = appendI64(b, 10, m.AtimeMs)
	b = appendI64(b, 11, m.BirthtimeMs)
	b = appendU64(b, 12, m.ContentVersion)
	if m.Parent != nil {
		b = appendMsg(b, 13, marshalItem(m.Parent))
	}
	b = appendU32(b, 14, m.Flags)
	b = appendU64(b, 15, m.AllocSize)
	return b
}

func parseAttrField(wt int, raw []byte) (Attr, error) {
	if wt != wireBytes {
		return Attr{}, ErrMalformed
	}
	m := Attr{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Kind = ItemKind(v)
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Mode = uint32(v)
		case 4:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Nlink = uint32(v)
		case 5:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.UID = uint32(v)
		case 6:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.GID = uint32(v)
		case 7:
			m.Size, err = scalarU64(wt, raw)
		case 8:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.MtimeMs = int64(v)
		case 9:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.CtimeMs = int64(v)
		case 10:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.AtimeMs = int64(v)
		case 11:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.BirthtimeMs = int64(v)
		case 12:
			m.ContentVersion, err = scalarU64(wt, raw)
		case 13:
			var parent Item
			parent, err = parseItemField(wt, raw)
			if err == nil {
				m.Parent = &parent
			}
		case 14:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Flags = uint32(v)
		case 15:
			m.AllocSize, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalErrorReply(m *ErrorReply) []byte {
	var b []byte
	b = appendI32(b, 1, m.Errno)
	b = appendString(b, 2, m.Message)
	return b
}

func unmarshalErrorReply(b []byte) (*ErrorReply, error) {
	m := &ErrorReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.Errno = int32(v)
			return err
		case 2:
			v, err := scalarBytes(wt, raw)
			m.Message = string(v)
			return err
		}
		return nil
	})
}

func marshalLookupRequest(m *LookupRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendBytesField(b, 2, m.Name)
	return b
}

func unmarshalLookupRequest(b []byte) (*LookupRequest, error) {
	m := &LookupRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Name, err = scalarBytes(wt, raw)
		}
		return err
	})
}

func marshalLookupReply(m *LookupReply) []byte {
	var b []byte
	return appendMsg(b, 1, marshalAttr(&m.Attr))
}

func unmarshalLookupReply(b []byte) (*LookupReply, error) {
	m := &LookupReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			a, err := parseAttrField(wt, raw)
			m.Attr = a
			return err
		}
		return nil
	})
}

func marshalEnumerateRequest(m *EnumerateRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendU64(b, 2, m.Cookie)
	b = appendU32(b, 3, m.MaxEntries)
	b = appendBool(b, 4, m.WantAttrs)
	return b
}

func unmarshalEnumerateRequest(b []byte) (*EnumerateRequest, error) {
	m := &EnumerateRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Cookie, err = scalarU64(wt, raw)
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.MaxEntries = uint32(v)
		case 4:
			m.WantAttrs, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalDirEntry(m *DirEntry) []byte {
	var b []byte
	b = appendBytesField(b, 1, m.Name)
	b = appendMsg(b, 2, marshalAttr(&m.Attr))
	b = appendU64(b, 3, m.Cookie)
	return b
}

func parseDirEntryField(wt int, raw []byte) (DirEntry, error) {
	if wt != wireBytes {
		return DirEntry{}, ErrMalformed
	}
	m := DirEntry{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Name, err = scalarBytes(wt, raw)
		case 2:
			m.Attr, err = parseAttrField(wt, raw)
		case 3:
			m.Cookie, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalEnumerateReply(m *EnumerateReply) []byte {
	var b []byte
	for i := range m.Entries {
		b = appendMsg(b, 1, marshalDirEntry(&m.Entries[i]))
	}
	b = appendU64(b, 2, m.NextCookie)
	b = appendU64(b, 3, m.DirVersion)
	return b
}

func unmarshalEnumerateReply(b []byte) (*EnumerateReply, error) {
	m := &EnumerateReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			var e DirEntry
			e, err = parseDirEntryField(wt, raw)
			m.Entries = append(m.Entries, e)
		case 2:
			m.NextCookie, err = scalarU64(wt, raw)
		case 3:
			m.DirVersion, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalGetAttrRequest(m *GetAttrRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendU64(b, 2, m.Handle)
	return b
}

func unmarshalGetAttrRequest(b []byte) (*GetAttrRequest, error) {
	m := &GetAttrRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			item, err := parseItemField(wt, raw)
			m.Item = item
			return err
		case 2:
			var err error
			m.Handle, err = scalarU64(wt, raw)
			return err
		}
		return nil
	})
}

func marshalGetAttrReply(m *GetAttrReply) []byte {
	var b []byte
	return appendMsg(b, 1, marshalAttr(&m.Attr))
}

func unmarshalGetAttrReply(b []byte) (*GetAttrReply, error) {
	m := &GetAttrReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			a, err := parseAttrField(wt, raw)
			m.Attr = a
			return err
		}
		return nil
	})
}

func marshalSetAttrRequest(m *SetAttrRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	if m.Mode != nil {
		b = appendU32Present(b, 2, *m.Mode)
	}
	if m.UID != nil {
		b = appendU32Present(b, 3, *m.UID)
	}
	if m.GID != nil {
		b = appendU32Present(b, 4, *m.GID)
	}
	if m.Size != nil {
		b = appendU64Present(b, 5, *m.Size)
	}
	if m.MtimeMs != nil {
		b = appendI64Present(b, 6, *m.MtimeMs)
	}
	if m.AtimeMs != nil {
		b = appendI64Present(b, 7, *m.AtimeMs)
	}
	b = appendU64(b, 8, m.Handle)
	return b
}

func unmarshalSetAttrRequest(b []byte) (*SetAttrRequest, error) {
	m := &SetAttrRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v uint64
			v, err = scalarU64(wt, raw)
			vv := uint32(v)
			m.Mode = &vv
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			vv := uint32(v)
			m.UID = &vv
		case 4:
			var v uint64
			v, err = scalarU64(wt, raw)
			vv := uint32(v)
			m.GID = &vv
		case 5:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Size = &v
		case 6:
			var v uint64
			v, err = scalarU64(wt, raw)
			vv := int64(v)
			m.MtimeMs = &vv
		case 7:
			var v uint64
			v, err = scalarU64(wt, raw)
			vv := int64(v)
			m.AtimeMs = &vv
		case 8:
			m.Handle, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalSetAttrReply(m *SetAttrReply) []byte {
	var b []byte
	return appendMsg(b, 1, marshalAttr(&m.Attr))
}

func unmarshalSetAttrReply(b []byte) (*SetAttrReply, error) {
	m := &SetAttrReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			a, err := parseAttrField(wt, raw)
			m.Attr = a
			return err
		}
		return nil
	})
}

func marshalOpenRequest(m *OpenRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendI32(b, 2, int32(m.Mode))
	b = appendBool(b, 3, m.Append)
	return b
}

func unmarshalOpenRequest(b []byte) (*OpenRequest, error) {
	m := &OpenRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Mode = OpenMode(v)
		case 3:
			m.Append, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalOpenReply(m *OpenReply) []byte {
	var b []byte
	return appendU64(b, 1, m.Handle)
}

func unmarshalOpenReply(b []byte) (*OpenReply, error) {
	m := &OpenReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarU64(wt, raw)
			m.Handle = v
			return err
		}
		return nil
	})
}

func marshalCloseRequest(m *CloseRequest) []byte {
	var b []byte
	return appendU64(b, 1, m.Handle)
}

func unmarshalCloseRequest(b []byte) (*CloseRequest, error) {
	m := &CloseRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarU64(wt, raw)
			m.Handle = v
			return err
		}
		return nil
	})
}

func marshalCloseReply(m *CloseReply) []byte {
	var b []byte
	b = appendBool(b, 1, m.Retired)
	b = appendI32(b, 2, m.CloseErrno)
	return b
}

func unmarshalCloseReply(b []byte) (*CloseReply, error) {
	m := &CloseReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			if err != nil {
				return err
			}
			m.Retired = v != 0
		case 2:
			v, err := scalarU64(wt, raw)
			if err != nil {
				return err
			}
			m.CloseErrno = int32(v)
		}
		return nil
	})
}

func marshalReadRequest(m *ReadRequest) []byte {
	var b []byte
	b = appendU64(b, 1, m.Handle)
	b = appendU64(b, 2, m.Offset)
	b = appendU32(b, 3, m.Length)
	return b
}

func unmarshalReadRequest(b []byte) (*ReadRequest, error) {
	m := &ReadRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Handle, err = scalarU64(wt, raw)
		case 2:
			m.Offset, err = scalarU64(wt, raw)
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Length = uint32(v)
		}
		return err
	})
}

func marshalReadReply(m *ReadReply) []byte {
	var b []byte
	return appendBytesField(b, 1, m.Data)
}

func unmarshalReadReply(b []byte) (*ReadReply, error) {
	m := &ReadReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarBytes(wt, raw)
			m.Data = v
			return err
		}
		return nil
	})
}

func marshalWriteRequest(m *WriteRequest) []byte {
	var b []byte
	b = appendU64(b, 1, m.Handle)
	b = appendU64(b, 2, m.Offset)
	b = appendBytesField(b, 3, m.Data)
	b = appendBool(b, 4, m.Append)
	return b
}

func unmarshalWriteRequest(b []byte) (*WriteRequest, error) {
	m := &WriteRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Handle, err = scalarU64(wt, raw)
		case 2:
			m.Offset, err = scalarU64(wt, raw)
		case 3:
			m.Data, err = scalarBytes(wt, raw)
		case 4:
			m.Append, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalWriteReply(m *WriteReply) []byte {
	var b []byte
	b = appendU32(b, 1, m.Written)
	b = appendMsg(b, 2, marshalAttr(&m.Attr))
	return b
}

func unmarshalWriteReply(b []byte) (*WriteReply, error) {
	m := &WriteReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Written = uint32(v)
		case 2:
			m.Attr, err = parseAttrField(wt, raw)
		}
		return err
	})
}

func marshalFsyncRequest(m *FsyncRequest) []byte {
	var b []byte
	return appendU64(b, 1, m.Handle)
}

func unmarshalFsyncRequest(b []byte) (*FsyncRequest, error) {
	m := &FsyncRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarU64(wt, raw)
			m.Handle = v
			return err
		}
		return nil
	})
}

func marshalCreateRequest(m *CreateRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendBytesField(b, 2, m.Name)
	b = appendU32(b, 3, m.Mode)
	b = appendBool(b, 4, m.Exclusive)
	b = appendBool(b, 5, m.Append)
	return b
}

func unmarshalCreateRequest(b []byte) (*CreateRequest, error) {
	m := &CreateRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Name, err = scalarBytes(wt, raw)
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Mode = uint32(v)
		case 4:
			m.Exclusive, err = scalarBool(wt, raw)
		case 5:
			m.Append, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalCreateReply(m *CreateReply) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalAttr(&m.Attr))
	b = appendU64(b, 2, m.Handle)
	return b
}

func unmarshalCreateReply(b []byte) (*CreateReply, error) {
	m := &CreateReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Attr, err = parseAttrField(wt, raw)
		case 2:
			m.Handle, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalMkdirRequest(m *MkdirRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendBytesField(b, 2, m.Name)
	b = appendU32(b, 3, m.Mode)
	return b
}

func unmarshalMkdirRequest(b []byte) (*MkdirRequest, error) {
	m := &MkdirRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Name, err = scalarBytes(wt, raw)
		case 3:
			var v uint64
			v, err = scalarU64(wt, raw)
			m.Mode = uint32(v)
		}
		return err
	})
}

func marshalMkdirReply(m *MkdirReply) []byte {
	var b []byte
	return appendMsg(b, 1, marshalAttr(&m.Attr))
}

func unmarshalMkdirReply(b []byte) (*MkdirReply, error) {
	m := &MkdirReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			a, err := parseAttrField(wt, raw)
			m.Attr = a
			return err
		}
		return nil
	})
}

func marshalRemoveRequest(m *RemoveRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendBytesField(b, 2, m.Name)
	b = appendBool(b, 3, m.Directory)
	return b
}

func unmarshalRemoveRequest(b []byte) (*RemoveRequest, error) {
	m := &RemoveRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Name, err = scalarBytes(wt, raw)
		case 3:
			m.Directory, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalRenameRequest(m *RenameRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.FromDir))
	b = appendBytesField(b, 2, m.FromName)
	b = appendMsg(b, 3, marshalItem(&m.ToDir))
	b = appendBytesField(b, 4, m.ToName)
	b = appendBool(b, 5, m.NoReplace)
	return b
}

func unmarshalRenameRequest(b []byte) (*RenameRequest, error) {
	m := &RenameRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.FromDir, err = parseItemField(wt, raw)
		case 2:
			m.FromName, err = scalarBytes(wt, raw)
		case 3:
			m.ToDir, err = parseItemField(wt, raw)
		case 4:
			m.ToName, err = scalarBytes(wt, raw)
		case 5:
			m.NoReplace, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalSymlinkRequest(m *SymlinkRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Dir))
	b = appendBytesField(b, 2, m.Name)
	b = appendBytesField(b, 3, m.Target)
	return b
}

func unmarshalSymlinkRequest(b []byte) (*SymlinkRequest, error) {
	m := &SymlinkRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Dir, err = parseItemField(wt, raw)
		case 2:
			m.Name, err = scalarBytes(wt, raw)
		case 3:
			m.Target, err = scalarBytes(wt, raw)
		}
		return err
	})
}

func marshalSymlinkReply(m *SymlinkReply) []byte {
	var b []byte
	return appendMsg(b, 1, marshalAttr(&m.Attr))
}

func unmarshalSymlinkReply(b []byte) (*SymlinkReply, error) {
	m := &SymlinkReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			a, err := parseAttrField(wt, raw)
			m.Attr = a
			return err
		}
		return nil
	})
}

func marshalReadlinkRequest(m *ReadlinkRequest) []byte {
	var b []byte
	return appendMsg(b, 1, marshalItem(&m.Item))
}

func unmarshalReadlinkRequest(b []byte) (*ReadlinkRequest, error) {
	m := &ReadlinkRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			item, err := parseItemField(wt, raw)
			m.Item = item
			return err
		}
		return nil
	})
}

func marshalReadlinkReply(m *ReadlinkReply) []byte {
	var b []byte
	return appendBytesField(b, 1, m.Target)
}

func unmarshalReadlinkReply(b []byte) (*ReadlinkReply, error) {
	m := &ReadlinkReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarBytes(wt, raw)
			m.Target = v
			return err
		}
		return nil
	})
}

func marshalHardLinkRequest(m *HardLinkRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendMsg(b, 2, marshalItem(&m.Dir))
	b = appendBytesField(b, 3, m.Name)
	return b
}

func unmarshalHardLinkRequest(b []byte) (*HardLinkRequest, error) {
	m := &HardLinkRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			m.Dir, err = parseItemField(wt, raw)
		case 3:
			m.Name, err = scalarBytes(wt, raw)
		}
		return err
	})
}

func marshalHardLinkReply(m *HardLinkReply) []byte {
	var b []byte
	b = appendBytesField(b, 1, m.Name)
	b = appendMsg(b, 2, marshalAttr(&m.Attr))
	return b
}

func unmarshalHardLinkReply(b []byte) (*HardLinkReply, error) {
	m := &HardLinkReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Name, err = scalarBytes(wt, raw)
		case 2:
			m.Attr, err = parseAttrField(wt, raw)
		}
		return err
	})
}

func marshalXattrGetRequest(m *XattrGetRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendString(b, 2, m.Name)
	b = appendU64(b, 3, m.Handle)
	return b
}

func unmarshalXattrGetRequest(b []byte) (*XattrGetRequest, error) {
	m := &XattrGetRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.Name = string(v)
		case 3:
			m.Handle, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalXattrGetReply(m *XattrGetReply) []byte {
	var b []byte
	return appendBytesField(b, 1, m.Value)
}

func unmarshalXattrGetReply(b []byte) (*XattrGetReply, error) {
	m := &XattrGetReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarBytes(wt, raw)
			m.Value = v
			return err
		}
		return nil
	})
}

func marshalXattrSetRequest(m *XattrSetRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendString(b, 2, m.Name)
	b = appendBytesField(b, 3, m.Value)
	b = appendBool(b, 4, m.CreateOnly)
	b = appendBool(b, 5, m.ReplaceOnly)
	b = appendU64(b, 6, m.Handle)
	return b
}

func unmarshalXattrSetRequest(b []byte) (*XattrSetRequest, error) {
	m := &XattrSetRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.Name = string(v)
		case 3:
			m.Value, err = scalarBytes(wt, raw)
		case 4:
			m.CreateOnly, err = scalarBool(wt, raw)
		case 5:
			m.ReplaceOnly, err = scalarBool(wt, raw)
		case 6:
			m.Handle, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalXattrListRequest(m *XattrListRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendU64(b, 2, m.Handle)
	return b
}

func unmarshalXattrListRequest(b []byte) (*XattrListRequest, error) {
	m := &XattrListRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			item, err := parseItemField(wt, raw)
			m.Item = item
			return err
		case 2:
			var err error
			m.Handle, err = scalarU64(wt, raw)
			return err
		}
		return nil
	})
}

func marshalXattrListReply(m *XattrListReply) []byte {
	var b []byte
	for _, name := range m.Names {
		b = appendString(b, 1, name)
	}
	return b
}

func unmarshalXattrListReply(b []byte) (*XattrListReply, error) {
	m := &XattrListReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			v, err := scalarBytes(wt, raw)
			m.Names = append(m.Names, string(v))
			return err
		}
		return nil
	})
}

func marshalXattrRemoveRequest(m *XattrRemoveRequest) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendString(b, 2, m.Name)
	b = appendU64(b, 3, m.Handle)
	return b
}

func unmarshalXattrRemoveRequest(b []byte) (*XattrRemoveRequest, error) {
	m := &XattrRemoveRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			var v []byte
			v, err = scalarBytes(wt, raw)
			m.Name = string(v)
		case 3:
			m.Handle, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalSyncVolumeReply(m *SyncVolumeReply) []byte {
	var b []byte
	b = appendBool(b, 1, m.Degraded)
	return b
}

func unmarshalSyncVolumeReply(b []byte) (*SyncVolumeReply, error) {
	m := &SyncVolumeReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		if num == 1 {
			m.Degraded, err = scalarBool(wt, raw)
		}
		return err
	})
}

func marshalStatfsReply(m *StatfsReply) []byte {
	var b []byte
	b = appendU64(b, 1, m.BlockSize)
	b = appendU64(b, 2, m.TotalBlocks)
	b = appendU64(b, 3, m.FreeBlocks)
	b = appendU64(b, 4, m.TotalFiles)
	b = appendU64(b, 5, m.FreeFiles)
	return b
}

func unmarshalStatfsReply(b []byte) (*StatfsReply, error) {
	m := &StatfsReply{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.BlockSize, err = scalarU64(wt, raw)
		case 2:
			m.TotalBlocks, err = scalarU64(wt, raw)
		case 3:
			m.FreeBlocks, err = scalarU64(wt, raw)
		case 4:
			m.TotalFiles, err = scalarU64(wt, raw)
		case 5:
			m.FreeFiles, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalReclaimRequest(m *ReclaimRequest) []byte {
	var b []byte
	return appendMsg(b, 1, marshalItem(&m.Item))
}

func unmarshalReclaimRequest(b []byte) (*ReclaimRequest, error) {
	m := &ReclaimRequest{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		if num == 1 {
			item, err := parseItemField(wt, raw)
			m.Item = item
			return err
		}
		return nil
	})
}

func marshalEvent(m *Event) []byte {
	var b []byte
	switch k := m.Kind.(type) {
	case *Invalidation:
		b = appendMsg(b, 1, marshalInvalidation(k))
	case *AttachState:
		b = appendMsg(b, 2, marshalAttachState(k))
	}
	return b
}

func unmarshalEvent(b []byte) (*Event, error) {
	m := &Event{}
	return m, scan(b, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			var inv Invalidation
			inv, err = parseInvalidationField(wt, raw)
			m.Kind = &inv
		case 2:
			var st AttachState
			st, err = parseAttachStateField(wt, raw)
			m.Kind = &st
		}
		return err
	})
}

func marshalInvalidation(m *Invalidation) []byte {
	var b []byte
	b = appendMsg(b, 1, marshalItem(&m.Item))
	b = appendBool(b, 2, m.ContentChanged)
	b = appendBool(b, 3, m.AttrsChanged)
	b = appendBool(b, 4, m.NamespaceChanged)
	b = appendU64(b, 5, m.ContentVersion)
	return b
}

func parseInvalidationField(wt int, raw []byte) (Invalidation, error) {
	if wt != wireBytes {
		return Invalidation{}, ErrMalformed
	}
	m := Invalidation{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		var err error
		switch num {
		case 1:
			m.Item, err = parseItemField(wt, raw)
		case 2:
			m.ContentChanged, err = scalarBool(wt, raw)
		case 3:
			m.AttrsChanged, err = scalarBool(wt, raw)
		case 4:
			m.NamespaceChanged, err = scalarBool(wt, raw)
		case 5:
			m.ContentVersion, err = scalarU64(wt, raw)
		}
		return err
	})
}

func marshalAttachState(m *AttachState) []byte {
	var b []byte
	b = appendI32(b, 1, int32(m.State))
	b = appendString(b, 2, m.Detail)
	return b
}

func parseAttachStateField(wt int, raw []byte) (AttachState, error) {
	if wt != wireBytes {
		return AttachState{}, ErrMalformed
	}
	m := AttachState{}
	return m, scan(raw, func(num int, wt int, raw []byte) error {
		switch num {
		case 1:
			v, err := scalarU64(wt, raw)
			m.State = AttachStateState(v)
			return err
		case 2:
			v, err := scalarBytes(wt, raw)
			m.Detail = string(v)
			return err
		}
		return nil
	})
}

func appendMsg(b []byte, num int, payload []byte) []byte {
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func appendBytesField(b []byte, num int, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendString(b []byte, num int, v string) []byte {
	if v == "" {
		return b
	}
	return appendBytesField(b, num, []byte(v))
}

func appendBool(b []byte, num int, v bool) []byte {
	if !v {
		return b
	}
	b = appendTag(b, num, wireVarint)
	return appendVarint(b, 1)
}

func appendU32(b []byte, num int, v uint32) []byte {
	if v == 0 {
		return b
	}
	return appendU32Present(b, num, v)
}

func appendU32Present(b []byte, num int, v uint32) []byte {
	b = appendTag(b, num, wireVarint)
	return appendVarint(b, uint64(v))
}

func appendU64(b []byte, num int, v uint64) []byte {
	if v == 0 {
		return b
	}
	return appendU64Present(b, num, v)
}

func appendU64Present(b []byte, num int, v uint64) []byte {
	b = appendTag(b, num, wireVarint)
	return appendVarint(b, v)
}

func appendI32(b []byte, num int, v int32) []byte {
	if v == 0 {
		return b
	}
	b = appendTag(b, num, wireVarint)
	return appendVarint(b, uint64(int64(v)))
}

func appendI64(b []byte, num int, v int64) []byte {
	if v == 0 {
		return b
	}
	return appendI64Present(b, num, v)
}

func appendI64Present(b []byte, num int, v int64) []byte {
	b = appendTag(b, num, wireVarint)
	return appendVarint(b, uint64(v))
}

func appendTag(b []byte, num int, wt int) []byte {
	return appendVarint(b, uint64(num<<3|wt))
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func consumeTag(b []byte) (int, int, []byte, error) {
	v, rest, err := consumeVarint(b)
	if err != nil {
		return 0, 0, nil, err
	}
	num, wt := int(v>>3), int(v&7)
	if num <= 0 {
		return 0, 0, nil, ErrMalformed
	}
	return num, wt, rest, nil
}

func consumeVarint(b []byte) (uint64, []byte, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if len(b) == 0 {
			return 0, nil, ErrMalformed
		}
		c := b[0]
		b = b[1:]
		if i == 9 && c > 1 {
			return 0, nil, ErrMalformed
		}
		v |= uint64(c&0x7f) << (uint(i) * 7)
		if c < 0x80 {
			return v, b, nil
		}
	}
	return 0, nil, ErrMalformed
}

func consumeBytes(b []byte) ([]byte, []byte, error) {
	n, rest, err := consumeVarint(b)
	if err != nil {
		return nil, nil, err
	}
	if n > uint64(len(rest)) {
		return nil, nil, ErrMalformed
	}
	return append([]byte(nil), rest[:n]...), rest[n:], nil
}

func skipValue(wt int, b []byte) ([]byte, error) {
	switch wt {
	case wireVarint:
		_, rest, err := consumeVarint(b)
		return rest, err
	case wireFixed64:
		if len(b) < 8 {
			return nil, ErrMalformed
		}
		return b[8:], nil
	case wireBytes:
		_, rest, err := consumeBytes(b)
		return rest, err
	case wireFixed32:
		if len(b) < 4 {
			return nil, ErrMalformed
		}
		return b[4:], nil
	default:
		return nil, ErrMalformed
	}
}

func scan(b []byte, fn func(num int, wt int, raw []byte) error) error {
	for len(b) > 0 {
		num, wt, rest, err := consumeTag(b)
		if err != nil {
			return err
		}
		var raw []byte
		switch wt {
		case wireVarint:
			var v uint64
			v, rest, err = consumeVarint(rest)
			if err != nil {
				return err
			}
			raw = appendVarint(nil, v)
		case wireFixed64:
			if len(rest) < 8 {
				return ErrMalformed
			}
			raw = append([]byte(nil), rest[:8]...)
			rest = rest[8:]
		case wireBytes:
			raw, rest, err = consumeBytes(rest)
			if err != nil {
				return err
			}
		case wireFixed32:
			if len(rest) < 4 {
				return ErrMalformed
			}
			raw = append([]byte(nil), rest[:4]...)
			rest = rest[4:]
		default:
			return ErrMalformed
		}
		if err := fn(num, wt, raw); err != nil {
			return err
		}
		b = rest
	}
	return nil
}

func scalarU64(wt int, raw []byte) (uint64, error) {
	if wt != wireVarint {
		return 0, ErrMalformed
	}
	v, rest, err := consumeVarint(raw)
	if err != nil {
		return 0, err
	}
	if len(rest) != 0 {
		return 0, ErrMalformed
	}
	return v, nil
}

func scalarBool(wt int, raw []byte) (bool, error) {
	v, err := scalarU64(wt, raw)
	return v != 0, err
}

func scalarBytes(wt int, raw []byte) ([]byte, error) {
	if wt != wireBytes {
		return nil, ErrMalformed
	}
	return append([]byte(nil), raw...), nil
}
