/**
 * Copyright 2008 The University of North Carolina at Chapel Hill
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fi.solita.clamav;

import java.nio.charset.StandardCharsets;

/**
 * Scan result wrapper.
 *
 * @author bbpennel
 * @author philvarner
 */
public class ScanResult {

    private String result;
    private Status status = Status.ERROR;
    private String signature;
    private Exception exception;

    public enum Status { PASSED, FOUND, ERROR }

    public static final String RESPONSE_OK = ": OK";
    public static final String FOUND_SUFFIX = "FOUND";
    public static final String ERROR_SUFFIX = "ERROR";

    public ScanResult(byte[] result) {
        setResult(new String(result, StandardCharsets.US_ASCII));
    }

    public ScanResult(Exception ex) {
        setException(ex);
        setStatus(Status.ERROR);
    }

    /**
     * @return Exception thrown by the scan
     */
    public Exception getException() {
        return exception;
    }

    public void setException(Exception exception) {
        this.exception = exception;
    }

    /**
     * @return the raw response output from the scan, as a string
     */
    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        if (result == null) {
            setStatus(Status.ERROR);
        }
        String normalized = result.replaceAll("\0", "").trim();
        this.result = normalized;
        if (normalized.endsWith(RESPONSE_OK)) {
            setStatus(Status.PASSED);
        } else if (normalized.endsWith(FOUND_SUFFIX)) {
            setStatus(Status.FOUND);
            setSignature(normalized.substring(normalized.lastIndexOf(':') + 2,
                    normalized.lastIndexOf(FOUND_SUFFIX) - 1));
        } else if (normalized.endsWith(ERROR_SUFFIX)) {
            setStatus(Status.ERROR);
        }
    }

    /**
     * @return Signature of the FOUND issue, or an empty string.
     */
    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * @return Status of the scan
     */
    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }
}
