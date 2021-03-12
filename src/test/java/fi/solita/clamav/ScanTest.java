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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @author bbpennel
 */
public class ScanTest {
    private static String CLAMAV_HOST = "localhost";
    private static final String EICAR =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    @Rule
    public final TemporaryFolder tmpFolder = new TemporaryFolder();

    private ClamAVClient client;

    @Before
    public void setup() throws Exception {
        tmpFolder.create();
        // Make sure clam has access to read the directory we are writing files to
        Files.setPosixFilePermissions(tmpFolder.getRoot().toPath(),
                PosixFilePermissions.fromString("rwxr-xr-x"));
        client = new ClamAVClient(CLAMAV_HOST, 3310);
    }

    @Test
    public void testPositive() throws Exception {
        Path scanPath = createTestFile(EICAR);

        ScanResult result = client.scanWithResult(scanPath);
        assertEquals(ScanResult.Status.FOUND, result.getStatus());
        String sig = result.getSignature().toLowerCase();
        assertTrue("Signature did not list eicar", sig.contains("eicar"));
    }

    @Test
    public void testPassed() throws Exception {
        Path scanPath = createTestFile("Random text here");
        ScanResult result = client.scanWithResult(scanPath);
        assertEquals(ScanResult.Status.PASSED, result.getStatus());
        assertNull(result.getSignature());
    }

    @Test
    public void testFileNotFound() throws Exception {
        File scanFile = new File(tmpFolder.getRoot(), "notExist.txt");
        ScanResult result = client.scanWithResult(scanFile.toPath());
        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertNull(result.getSignature());
    }

    private Path createTestFile(String content) throws IOException {
        Path scanPath = tmpFolder.newFile().toPath();
        Files.write(scanPath, content.getBytes("ASCII"));
        Files.setPosixFilePermissions(scanPath, PosixFilePermissions.fromString("rw-rw-r--"));
        return scanPath;
    }
}
