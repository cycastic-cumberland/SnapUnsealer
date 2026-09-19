//
//  RootView.swift
//  SnapUnsealer
//

import SwiftUI

/// Routes between enrollment (Job 1) and decrypt (Job 2) based on whether a
/// wrapped key already exists in Keychain.
struct RootView: View {
    @State private var isEnrolled = UnsealerService.isEnrolled()

    var body: some View {
        Group {
            if isEnrolled {
                DecryptView {
                    UnsealerService.replaceEnrolledKey()
                    isEnrolled = false
                }
            } else {
                EnrollmentView {
                    isEnrolled = true
                }
            }
        }
    }
}

#Preview {
    RootView()
}
