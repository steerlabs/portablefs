// Code generated from proto/workspace/v8/control.proto. DO NOT EDIT.
import Foundation

enum WorkspaceWireSchema {
    static let messages: [String: [UInt64: WorkspaceWireField]] = [
        "Release": [
            1: .init(kind: "$", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "", repeated: false, oneof: false),
        ],
        "Hello": [
            1: .init(kind: "Release", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "$", repeated: false, oneof: false),
        ],
        "MountID": [
            1: .init(kind: "$", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
        ],
        "Suspension": [
            1: .init(kind: "$", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "", repeated: false, oneof: false),
            5: .init(kind: "MountID", repeated: true, oneof: false),
            6: .init(kind: "$", repeated: false, oneof: false),
        ],
        "Loss": [
            1: .init(kind: "", repeated: false, oneof: false),
            2: .init(kind: "", repeated: false, oneof: false),
            3: .init(kind: "", repeated: false, oneof: false),
            4: .init(kind: "$", repeated: false, oneof: false),
            5: .init(kind: "", repeated: false, oneof: false),
        ],
        "MountCold": [
            1: .init(kind: "MountID", repeated: false, oneof: false),
            3: .init(kind: "Loss", repeated: true, oneof: false),
        ],
        "SuspendAck": [
            1: .init(kind: "Suspension", repeated: false, oneof: false),
            2: .init(kind: "MountCold", repeated: true, oneof: false),
        ],
        "ResumeToken": [
            1: .init(kind: "Suspension", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
        ],
        "MountStatus": [
            1: .init(kind: "MountID", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "Loss", repeated: true, oneof: false),
            5: .init(kind: "$", repeated: false, oneof: false),
        ],
        "ResumeAck": [
            1: .init(kind: "ResumeToken", repeated: false, oneof: false),
            2: .init(kind: "MountStatus", repeated: true, oneof: false),
        ],
        "StatusRequest": [
            :
        ],
        "StatusReply": [
            1: .init(kind: "$", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "", repeated: false, oneof: false),
            5: .init(kind: "$", repeated: false, oneof: false),
            6: .init(kind: "MountStatus", repeated: true, oneof: false),
            7: .init(kind: "MountStatus", repeated: true, oneof: false),
        ],
        "RetireAck": [
            1: .init(kind: "MountStatus", repeated: true, oneof: false),
        ],
        "Provision": [
            1: .init(kind: "MountID", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
            3: .init(kind: "$", repeated: false, oneof: false),
            4: .init(kind: "$", repeated: false, oneof: false),
            5: .init(kind: "$", repeated: false, oneof: false),
            6: .init(kind: "$", repeated: false, oneof: false),
            7: .init(kind: "$", repeated: false, oneof: false),
        ],
        "MountRequest": [
            1: .init(kind: "MountID", repeated: false, oneof: false),
        ],
        "UmountRequest": [
            1: .init(kind: "MountID", repeated: false, oneof: false),
        ],
        "Result": [
            1: .init(kind: "$", repeated: false, oneof: false),
            2: .init(kind: "$", repeated: false, oneof: false),
        ],
        "Envelope": [
            1: .init(kind: "", repeated: false, oneof: false),
            2: .init(kind: "", repeated: false, oneof: false),
            10: .init(kind: "Hello", repeated: false, oneof: true),
            11: .init(kind: "Hello", repeated: false, oneof: true),
            12: .init(kind: "Suspension", repeated: false, oneof: true),
            13: .init(kind: "SuspendAck", repeated: false, oneof: true),
            14: .init(kind: "ResumeToken", repeated: false, oneof: true),
            15: .init(kind: "ResumeAck", repeated: false, oneof: true),
            16: .init(kind: "StatusRequest", repeated: false, oneof: true),
            17: .init(kind: "StatusReply", repeated: false, oneof: true),
            18: .init(kind: "Provision", repeated: false, oneof: true),
            19: .init(kind: "MountRequest", repeated: false, oneof: true),
            20: .init(kind: "UmountRequest", repeated: false, oneof: true),
            21: .init(kind: "Result", repeated: false, oneof: true),
            22: .init(kind: "RetireAck", repeated: false, oneof: true),
        ],
    ]
}
