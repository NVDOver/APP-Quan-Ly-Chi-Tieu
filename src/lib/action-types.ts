/**
 * Type chuẩn cho tất cả Server Action responses.
 * Đảm bảo consistency toàn bộ codebase.
 */
export type ActionResult<T = undefined> =
    | { success: true; data?: T }
    | { success: false; error: string };

/**
 * Helper để tạo success result
 */
export function actionSuccess<T>(data?: T): ActionResult<T> {
    return { success: true, data };
}

/**
 * Helper để tạo error result từ unknown error
 */
export function actionError(error: unknown, fallback = "Đã xảy ra lỗi"): ActionResult {
    if (error instanceof Error) {
        return { success: false, error: error.message };
    }
    return { success: false, error: fallback };
}