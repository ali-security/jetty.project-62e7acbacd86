//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.util.resource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.InvalidPathException;

import org.eclipse.jetty.toolchain.test.FS;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.junit.Assume;
import org.junit.Test;

/**
 * Regression test for the CVE-2019-10241 fix in {@link Resource#getListHTML(String, boolean)}:
 * the {@code base} (request path) must be href-encoded before it is reflected into the
 * Parent-Directory link, otherwise a crafted path yields reflected XSS.
 */
public class ResourceListHTMLTest
{
    private static final String PARENT_LINK_END = "\">Parent Directory</A>";

    private static File newTestDir(String name) throws IOException
    {
        File dir = MavenTestingUtils.getTargetTestingDir(ResourceListHTMLTest.class.getSimpleName() + "-" + name);
        FS.ensureDirExists(dir);
        FS.ensureEmpty(dir);
        assertTrue(new File(dir, "child.txt").createNewFile());
        return dir;
    }

    private static String parentHref(String listing)
    {
        int end = listing.indexOf(PARENT_LINK_END);
        assertTrue("Parent Directory link missing in: " + listing, end > 0);
        int start = listing.lastIndexOf("HREF=\"", end);
        assertTrue("Parent Directory HREF missing in: " + listing, start >= 0);
        return listing.substring(start + "HREF=\"".length(), end);
    }

    @Test
    public void testListHTMLParentLinkEncodesXSS() throws Exception
    {
        Resource resource = Resource.newResource(newTestDir("script"));
        try
        {
            String base = "/ctx/\"><script>alert(1)</script>/";
            String listing = resource.getListHTML(base, true);
            assertNotNull(listing);

            // CVE-2019-10241: the raw XSS payload must never be reflected verbatim...
            assertFalse("raw XSS payload must not be reflected in the listing: " + listing,
                listing.contains("\"><script>"));
            assertFalse("raw script tag must not be reflected in the listing: " + listing,
                listing.contains("<script>"));
            // ...it must appear href-encoded instead (proof the fix is active).
            assertTrue("base must be href-encoded (expected %3Cscript%3E) in: " + listing,
                listing.contains("%3Cscript%3E"));
            assertEquals("/ctx/%22%3E%3Cscript%3Ealert(1)%3C/script%3E/../", parentHref(listing));
        }
        finally
        {
            resource.close();
        }
    }

    @Test
    public void testListHTMLParentLinkEncodesQuotes() throws Exception
    {
        Resource resource = Resource.newResource(newTestDir("quote"));
        try
        {
            String base = "/ctx/'onmouseover='alert(1)'\"><script>alert('xss')</script>/";
            String listing = resource.getListHTML(base, true);
            assertNotNull(listing);

            String href = parentHref(listing);
            assertFalse("raw single quote must not be reflected in the parent link: " + href,
                href.contains("'"));
            assertFalse("raw double quote must not be reflected in the parent link: " + href,
                href.contains("\""));
            assertFalse("raw angle bracket must not be reflected in the parent link: " + href,
                href.contains("<") || href.contains(">"));
            assertEquals("/ctx/%27onmouseover=%27alert(1)%27%22%3E%3Cscript%3Ealert(%27xss%27)%3C/script%3E/../", href);
            assertTrue("parent link must be href-encoded in: " + listing,
                listing.contains("<A HREF=\"" + href + PARENT_LINK_END));
            assertFalse("raw script tag must not be reflected in the listing: " + listing,
                listing.contains("<script>"));
        }
        finally
        {
            resource.close();
        }
    }

    @Test
    public void testListHTMLItemNameEncodesXSS() throws Exception
    {
        File dir = newTestDir("item");
        String name = "\"><img src=x onerror=alert(1)>.txt";
        boolean created;
        try
        {
            created = new File(dir, name).createNewFile();
        }
        catch (IOException | InvalidPathException e)
        {
            created = false;
        }
        // Some file systems (eg Windows) do not allow these characters in file names
        Assume.assumeTrue(created);

        Resource resource = Resource.newResource(dir);
        try
        {
            String listing = resource.getListHTML("/ctx/", true);
            assertNotNull(listing);

            assertFalse("raw file name must not be reflected in the listing: " + listing,
                listing.contains("<img"));
            assertTrue("file name must be href-encoded in: " + listing,
                listing.contains("/ctx/%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E.txt\">"));
            assertTrue("file name must be escaped in the link text of: " + listing,
                listing.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;.txt"));
        }
        finally
        {
            resource.close();
        }
    }
}
