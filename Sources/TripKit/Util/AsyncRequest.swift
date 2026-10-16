import Foundation

public class AsyncRequest {
    
    var task: URLSessionTask?
    var cancelHandler: (() -> Void)?

    public init(task: URLSessionTask?) {
        self.task = task
    }

    init(cancelHandler: @escaping () -> Void) {
        self.cancelHandler = cancelHandler
    }

    public func cancel() {
        task?.cancel()
        cancelHandler?()
    }
    
}
