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

import java.io.File;
import java.nio.file.Files;

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
        client = new ClamAVClient(CLAMAV_HOST, 3310);
    }

    @Test
    public void testPositive() throws Exception {
        File scanFile = tmpFolder.newFile();
        Files.write(scanFile.toPath(), EICAR.getBytes("ASCII"));
        ScanResult result = client.scanWithResult(scanFile.toPath());
        assertEquals(ScanResult.Status.FOUND, result.getStatus());
        assertEquals("Win.Test.EICAR_HDB-1", result.getSignature());
    }

    @Test
    public void testPassed() throws Exception {
        File scanFile = tmpFolder.newFile();
        Files.write(scanFile.toPath(), "Random text here".getBytes());
        ScanResult result = client.scanWithResult(scanFile.toPath());
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
}
