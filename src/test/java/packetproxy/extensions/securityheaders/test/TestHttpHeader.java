/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.extensions.securityheaders.test;

import packetproxy.http.HttpHeader;

/**
 * Helper class to create HttpHeader instances for testing. Builds HTTP response
 * headers with specified header fields.
 */
public class TestHttpHeader {

	private final StringBuilder headerBuilder;

	public TestHttpHeader() {
		this.headerBuilder = new StringBuilder();
		this.headerBuilder.append("HTTP/1.1 200 OK\r\n");
	}

	public TestHttpHeader(String statusLine) {
		this.headerBuilder = new StringBuilder();
		this.headerBuilder.append(statusLine).append("\r\n");
	}

	public TestHttpHeader addHeader(String name, String value) {
		headerBuilder.append(name).append(": ").append(value).append("\r\n");
		return this;
	}

	public HttpHeader build() {
		headerBuilder.append("\r\n");
		return new HttpHeader(headerBuilder.toString().getBytes());
	}

	// ===== Static Factory Methods for Common Test Cases =====

	public static HttpHeader empty() {
		return new TestHttpHeader().build();
	}

	public static HttpHeader withCsp(String cspValue) {
		return new TestHttpHeader().addHeader("Content-Security-Policy", cspValue).build();
	}

	public static HttpHeader withXFrameOptions(String xfoValue) {
		return new TestHttpHeader().addHeader("X-Frame-Options", xfoValue).build();
	}

	public static HttpHeader withSetCookie(String cookieValue) {
		return new TestHttpHeader().addHeader("Set-Cookie", cookieValue).build();
	}

	public static HttpHeader withHsts(String hstsValue) {
		return new TestHttpHeader().addHeader("Strict-Transport-Security", hstsValue).build();
	}

	public static HttpHeader withContentType(String contentTypeValue) {
		return new TestHttpHeader().addHeader("Content-Type", contentTypeValue).build();
	}

	public static HttpHeader withCacheControl(String cacheControlValue) {
		return new TestHttpHeader().addHeader("Cache-Control", cacheControlValue).build();
	}

	public static HttpHeader withCors(String corsValue) {
		return new TestHttpHeader().addHeader("Access-Control-Allow-Origin", corsValue).build();
	}

	public static HttpHeader withXContentTypeOptions(String value) {
		return new TestHttpHeader().addHeader("X-Content-Type-Options", value).build();
	}
}
