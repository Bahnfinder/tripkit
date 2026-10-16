import Foundation
import os.log
import SwiftyJSON
import SWXMLHash

public class HttpClient: NSObject {
    
    private static var shared = HttpClient()
    private static let DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/602.4.8 (KHTML, like Gecko) Version/10.0.3 Safari/602.4.8"
    
    /// Akamai (e.g. app.services-bahn.de) answers HTTP 452 OPS_BLOCKED depending on the TLS client fingerprint,
    /// and which TLS version gets blocked changes over time. On a 452 the request is retried once with the other
    /// TLS version, and the version that worked is remembered per host. DB Fix
    private static let blockedStatusCode = 452
    /// Hosts that block every URLSession/Network.framework TLS fingerprint and are requested via StreamHttpTask instead. DB Fix
    private static let streamHosts: Set<String> = ["app.services-bahn.de"]
    private var tls12PreferredHosts: Set<String> = []
    private let tls12PreferredHostsLock = NSLock()

    private lazy var urlSession: URLSession = makeUrlSession(limitToTLS12: false)
    private lazy var tls12UrlSession: URLSession = makeUrlSession(limitToTLS12: true)

    private func makeUrlSession(limitToTLS12: Bool) -> URLSession {
        let config = URLSessionConfiguration.default
        if #available(iOS 11.0, tvOS 11.0, watchOS 4.0, macOS 10.13, *) {
            config.waitsForConnectivity = true
        }
        if limitToTLS12 {
            config.tlsMaximumSupportedProtocolVersion = .TLSv12
        }
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    private func prefersTLS12(host: String?) -> Bool {
        guard let host = host else { return false }
        tls12PreferredHostsLock.lock()
        defer { tls12PreferredHostsLock.unlock() }
        return tls12PreferredHosts.contains(host)
    }

    private func setPrefersTLS12(_ prefersTLS12: Bool, host: String?) {
        guard let host = host else { return }
        tls12PreferredHostsLock.lock()
        defer { tls12PreferredHostsLock.unlock() }
        if prefersTLS12 {
            tls12PreferredHosts.insert(host)
        } else {
            tls12PreferredHosts.remove(host)
        }
    }
    private var clientIdentityCache: [String: SecIdentity] = [:]
    private var clientRootCache: [String: SecCertificate] = [:]
    
    public static func get(httpRequest: HttpRequest, completion: @escaping (Result<(HTTPURLResponse, Data), HttpError>) -> Void) -> AsyncRequest {
        guard let url = httpRequest.urlBuilder.build() else {
            os_log("Failed to parse http url %{public}@", log: .requestLogger, type: .error, httpRequest.urlBuilder.getPath() ?? "<unknown>")
            completion(.failure(.invalidUrl(httpRequest.urlBuilder.getPath())))
            return AsyncRequest(task: nil)
        }
        
        var urlRequest = URLRequest(url: url)
        urlRequest.setValue(httpRequest.userAgent ?? DefaultUserAgent, forHTTPHeaderField: "User-Agent")
        
        if let payload = httpRequest.postPayload {
            urlRequest.httpMethod = "POST"
            urlRequest.setValue(httpRequest.contentType ?? "application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.httpBody = payload.data(using: .utf8) // TODO: don't hardcode encoding
        }
        
        for (header, value) in httpRequest.headers ?? [:] {
            urlRequest.setValue(value, forHTTPHeaderField: header)
        }
        
        if let payload = httpRequest.postPayload {
            os_log("making http request to %{public}@: %{public}@", log: .requestLogger, type: .default, url.absoluteString, payload.replacingOccurrences(of: "\"auth\":\\s*(\\{[^}]*\\})", with: "\"auth\":<private>", options: .regularExpression))
        } else {
            os_log("making http request to %{public}@", log: .requestLogger, type: .default, url.absoluteString)
        }
        let host = url.host
        if let host = host, streamHosts.contains(host) {
            let streamTask = StreamHttpTask(urlRequest: urlRequest)
            streamTask.resume(completion: completion)
            return AsyncRequest(cancelHandler: streamTask.cancel)
        }
        let useTLS12 = shared.prefersTLS12(host: host)
        let asyncRequest = AsyncRequest(task: nil)
        let task = shared.session(limitToTLS12: useTLS12).dataTask(with: urlRequest) { result in
            guard case .failure(.invalidStatusCode(blockedStatusCode, _)) = result else {
                completion(result)
                return
            }
            // Request was blocked, retry once with the other TLS version
            os_log("request to %{public}@ blocked (TLS 1.2 only: %{public}@), retrying with other TLS version", log: .requestLogger, type: .default, url.absoluteString, String(describing: useTLS12))
            let retryTask = shared.session(limitToTLS12: !useTLS12).dataTask(with: urlRequest) { retryResult in
                if case .success = retryResult {
                    shared.setPrefersTLS12(!useTLS12, host: host)
                }
                completion(retryResult)
            }
            asyncRequest.task = retryTask
            retryTask.resume()
        }
        asyncRequest.task = task
        task.resume()

        return asyncRequest
    }

    private func session(limitToTLS12: Bool) -> URLSession {
        return limitToTLS12 ? tls12UrlSession : urlSession
    }
    
    public static func getJson(httpRequest: HttpRequest, completion: @escaping (Result<JSON, HttpError>) -> Void) -> AsyncRequest {
        return get(httpRequest: httpRequest) { result in
            switch result {
            case .success((_, let data)):
                do {
                    let json = try JSON(data: data)
                    completion(.success(json))
                } catch let err {
                    os_log("failed to parse json from http response: %{public}@", log: .requestLogger, type: .error, String(describing: err))
                    completion(.failure(.parseError))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    public static func getXml(httpRequest: HttpRequest, completion: @escaping (Result<XMLIndexer, HttpError>) -> Void) -> AsyncRequest {
        return get(httpRequest: httpRequest) { result in
            switch result {
            case .success((_, let data)):
                let xml = XMLHash.parse(data)
                completion(.success(xml))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
}

extension HttpClient: URLSessionDelegate {
    public static func cacheIdentity(for host: String, identity: SecIdentity) {
        shared.clientIdentityCache[host] = identity
    }
    
    public static func cacheRootCertificate(for host: String, certificate: SecCertificate) {
        shared.clientRootCache[host] = certificate
    }
    
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        switch (challenge.protectionSpace.authenticationMethod) {
        case NSURLAuthenticationMethodClientCertificate:
            if let identity = clientIdentityCache[challenge.protectionSpace.host] {
                completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        case NSURLAuthenticationMethodServerTrust:
            if let rootCert = clientRootCache[challenge.protectionSpace.host], let trust = challenge.protectionSpace.serverTrust {
                if trust.evaluateAllowing(rootCertificates: [rootCert]) {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                } else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}


public enum HttpError: Error {
    case invalidUrl(String?)
    case invalidStatusCode(Int, Data)
    case networkError(Error)
    case parseError
}

extension URLSession {
    func dataTask(with urlRequest: URLRequest, result: @escaping (Result<(HTTPURLResponse, Data), HttpError>) -> Void) -> URLSessionDataTask {
        return dataTask(with: urlRequest) { (data, response, err) in
            if let err = err {
                os_log("failed to execute http request: %{public}@", log: .requestLogger, type: .error, String(describing: err))
                    result(.failure(.networkError(err)))
                return
            }
            guard let response = response as? HTTPURLResponse, let data = data else {
                os_log("failed to parse http response", log: .requestLogger, type: .error)
                result(.failure(.parseError))
                return
            }
            guard response.statusCode / 100 == 2 else {
                os_log("got invalid http status code %d", log: .requestLogger, type: .error, response.statusCode)
                result(.failure(.invalidStatusCode(response.statusCode, data)))
                return
            }
            result(.success((response, data)))
        }
    }
}

// MARK: StreamHttpTask

/// Minimal HTTP/1.1 client on top of CFStream (SecureTransport). Akamai blocks the TLS fingerprint of
/// URLSession/Network.framework for app.services-bahn.de (HTTP 452 OPS_BLOCKED) but accepts this one. DB Fix
final class StreamHttpTask {

    private static let timeout: TimeInterval = 30
    private static let pollInterval: useconds_t = 5_000
    private static let headerSeparator = Data("\r\n\r\n".utf8)
    private static let lineSeparator = Data("\r\n".utf8)

    private let urlRequest: URLRequest
    private let lock = NSLock()
    private var cancelled = false

    init(urlRequest: URLRequest) {
        self.urlRequest = urlRequest
    }

    func resume(completion: @escaping (Result<(HTTPURLResponse, Data), HttpError>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            completion(self.perform())
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    private var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    private func perform() -> Result<(HTTPURLResponse, Data), HttpError> {
        guard let url = urlRequest.url, let host = url.host else {
            return .failure(.invalidUrl(urlRequest.url?.absoluteString))
        }
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getStreamsToHost(withName: host, port: url.port ?? 443, inputStream: &inputStream, outputStream: &outputStream)
        guard let input = inputStream, let output = outputStream else {
            return .failure(.networkError(URLError(.cannotConnectToHost)))
        }
        input.setProperty(StreamSocketSecurityLevel.negotiatedSSL, forKey: .socketSecurityLevelKey)
        output.setProperty(StreamSocketSecurityLevel.negotiatedSSL, forKey: .socketSecurityLevelKey)
        input.open()
        output.open()
        defer {
            input.close()
            output.close()
        }

        let deadline = Date().addingTimeInterval(StreamHttpTask.timeout)
        let data: Data
        do {
            try write(requestData(url: url, host: host), to: output, deadline: deadline)
            data = try readResponse(from: input, deadline: deadline)
        } catch let err {
            os_log("failed to execute http request: %{public}@", log: .requestLogger, type: .error, String(describing: err))
            return .failure(.networkError(err))
        }

        guard let (response, body) = StreamHttpTask.parse(response: data, url: url) else {
            os_log("failed to parse http response", log: .requestLogger, type: .error)
            return .failure(.parseError)
        }
        guard response.statusCode / 100 == 2 else {
            os_log("got invalid http status code %d", log: .requestLogger, type: .error, response.statusCode)
            return .failure(.invalidStatusCode(response.statusCode, body))
        }
        return .success((response, body))
    }

    private func requestData(url: URL, host: String) -> Data {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var target = components?.percentEncodedPath ?? "/"
        if target.isEmpty { target = "/" }
        if let query = components?.percentEncodedQuery { target += "?" + query }

        var head = "\(urlRequest.httpMethod ?? "GET") \(target) HTTP/1.1\r\n"
        head += "Host: \(url.port.map { "\(host):\($0)" } ?? host)\r\n"
        for (header, value) in urlRequest.allHTTPHeaderFields ?? [:] {
            head += "\(header): \(value)\r\n"
        }
        if let body = urlRequest.httpBody {
            head += "Content-Length: \(body.count)\r\n"
        }
        head += "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"

        var data = Data(head.utf8)
        if let body = urlRequest.httpBody {
            data.append(body)
        }
        return data
    }

    private func checkState(of stream: Stream, deadline: Date) throws {
        if isCancelled { throw URLError(.cancelled) }
        if Date() > deadline { throw URLError(.timedOut) }
        if stream.streamStatus == .error { throw stream.streamError ?? URLError(.networkConnectionLost) }
    }

    private func write(_ data: Data, to output: OutputStream, deadline: Date) throws {
        let bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            try checkState(of: output, deadline: deadline)
            guard output.hasSpaceAvailable else {
                usleep(StreamHttpTask.pollInterval)
                continue
            }
            let written = bytes.withUnsafeBufferPointer { output.write($0.baseAddress! + offset, maxLength: bytes.count - offset) }
            if written < 0 { throw output.streamError ?? URLError(.networkConnectionLost) }
            offset += written
        }
    }

    private func readResponse(from input: InputStream, deadline: Date) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            try checkState(of: input, deadline: deadline)
            guard input.hasBytesAvailable else {
                if input.streamStatus == .atEnd { break }
                usleep(StreamHttpTask.pollInterval)
                continue
            }
            let read = input.read(&buffer, maxLength: buffer.count)
            if read < 0 { throw input.streamError ?? URLError(.networkConnectionLost) }
            if read == 0 { break }
            data.append(buffer, count: read)
            // don't wait for the server to close the connection once the response is complete
            if StreamHttpTask.parse(response: data, url: nil) != nil { break }
        }
        return data
    }

    /// Returns nil if the response is incomplete or malformed. The response object is only created if url is given.
    private static func parse(response data: Data, url: URL?) -> (HTTPURLResponse, Data)? {
        guard let headerEnd = data.range(of: headerSeparator), let head = String(data: data[..<headerEnd.lowerBound], encoding: .isoLatin1) else { return nil }
        var lines = head.components(separatedBy: "\r\n")
        let statusLine = lines.removeFirst().split(separator: " ", maxSplits: 2)
        guard statusLine.count >= 2, let statusCode = Int(statusLine[1]) else { return nil }

        var headerFields: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headerFields[String(line[..<colon])] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        func headerValue(_ name: String) -> String? {
            return headerFields.first(where: { $0.key.caseInsensitiveCompare(name) == .orderedSame })?.value
        }

        var body = Data(data[headerEnd.upperBound...])
        if headerValue("Transfer-Encoding")?.lowercased().contains("chunked") == true {
            guard let decoded = decodeChunked(body) else { return nil }
            body = decoded
        } else if let contentLength = headerValue("Content-Length").flatMap({ Int($0) }) {
            guard body.count >= contentLength else { return nil }
            body = body.prefix(contentLength)
        } else if url == nil {
            // body is terminated by the end of the connection
            return nil
        }

        let response = HTTPURLResponse(url: url ?? URL(fileURLWithPath: "/"), statusCode: statusCode, httpVersion: String(statusLine[0]), headerFields: headerFields)
        return response.map { ($0, body) }
    }

    /// Returns nil if the chunked body is incomplete or malformed.
    private static func decodeChunked(_ data: Data) -> Data? {
        var result = Data()
        var index = data.startIndex
        while true {
            guard let lineEnd = data.range(of: lineSeparator, in: index..<data.endIndex),
                  let sizeLine = String(data: data[index..<lineEnd.lowerBound], encoding: .ascii),
                  let size = Int(sizeLine.split(separator: ";").first?.trimmingCharacters(in: .whitespaces) ?? "", radix: 16)
            else { return nil }
            index = lineEnd.upperBound
            if size == 0 { return result }
            guard data.distance(from: index, to: data.endIndex) >= size + lineSeparator.count else { return nil }
            result.append(data[index..<data.index(index, offsetBy: size)])
            index = data.index(index, offsetBy: size + lineSeparator.count)
        }
    }

}

public class HttpRequest {
    public let urlBuilder: UrlBuilder
    public var postPayload: String?
    public var contentType: String?
    public var userAgent: String?
    public var headers: [String: String]?
    /// the response to this request
    public var responseData: Data?
    
    public init(urlBuilder: UrlBuilder) {
        self.urlBuilder = urlBuilder
    }
    
    @discardableResult
    public func setPostPayload(_ postPayload: String?) -> Self {
        self.postPayload = postPayload
        return self
    }
    
    @discardableResult
    public func setContentType(_ contentType: String?) -> Self {
        self.contentType = contentType
        return self
    }
    
    @discardableResult
    public func setUserAgent(_ userAgent: String?) -> Self {
        self.userAgent = userAgent
        return self
    }
    
    @discardableResult
    public func setHeaders(_ headers: [String: String]?) -> Self {
        self.headers = headers
        return self
    }
    
}

extension Data {
    
    func encodedData(encoding: String.Encoding) -> Data? {
        let encodedData: Data?
        if encoding == .utf8 {
            encodedData = self
        } else {
            let string = String(data: self, encoding: encoding)
            encodedData = string?.data(using: .utf8, allowLossyConversion: true)
        }
        return encodedData
    }
    
    func toJson(encoding: String.Encoding = .utf8) throws -> Any? {
        if let encodedData = encodedData(encoding: encoding) {
            return try JSONSerialization.jsonObject(with: encodedData, options: .allowFragments)
        } else {
            return nil
        }
    }
    
}

extension String {
    
    public func decodeUrl(using encoding: String.Encoding) -> String? {
        return (self as NSString).replacingPercentEscapes(using: encoding.rawValue)
    }
    
    public func encodeUrl(using encoding: String.Encoding) -> String? {
        return (self as NSString).addingPercentEscapes(using: encoding.rawValue)
    }
    
}
