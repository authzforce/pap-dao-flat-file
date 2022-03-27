/*
 * Copyright (C) 2012-2022 THALES.
 *
 * This file is part of AuthzForce CE.
 *
 * AuthzForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthzForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthzForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.flatfile;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import org.apache.cxf.helpers.MapNamespaceContext;
import org.apache.cxf.staxutils.DelegatingXMLStreamWriter;

import javax.xml.namespace.NamespaceContext;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Map;

/**
 * {@link XMLStreamWriter} appending extra XML namespaces
 */
public final class XmlnsAppendingDelegatingXMLStreamWriter extends DelegatingXMLStreamWriter
{
    private static final UnsupportedOperationException UNSUPPORTED_OPERATION_EXCEPTION = new UnsupportedOperationException();
    private final ImmutableMap<String, String> xpathNamespaceContexts;
    private boolean xpathNsAppended = false;

    /**
     *
     * @param delegate wrapped {@link XMLStreamWriter} to which operations are delegated
     * @param xmlNamespaceContexts XML namespace prefix-to-URI mappings
     * @throws XMLStreamException error that might occur when calling {@link XMLStreamWriter#setNamespaceContext(NamespaceContext)} or {@link XMLStreamWriter#setPrefix(String, String)} on the {@code delegate}
     */
    public XmlnsAppendingDelegatingXMLStreamWriter(final XMLStreamWriter delegate, final ImmutableMap<String, String> xmlNamespaceContexts) throws XMLStreamException
    {
        super(delegate);
        Preconditions.checkArgument(delegate != null);
        Preconditions.checkArgument(xmlNamespaceContexts != null);
        try
        {
            super.setNamespaceContext(new MapNamespaceContext(xmlNamespaceContexts));
        } catch(UnsupportedOperationException e) {
            for (final Map.Entry<String, String> nsEntry : xmlNamespaceContexts.entrySet())
            {
                super.setPrefix(nsEntry.getKey(), nsEntry.getValue());
            }
        }
        // Once NamespaceContext is set, writeNamespace() and writeDefaultNamespace() are no longer called.
        this.xpathNamespaceContexts = xmlNamespaceContexts;
    }

    private void appendNamespaces() throws XMLStreamException
    {
        if (xpathNsAppended)
        {
            return;
        }

        for (final Map.Entry<String, String> nsContext : xpathNamespaceContexts.entrySet())
        {
            super.writeNamespace(nsContext.getKey(), nsContext.getValue());
        }
        xpathNsAppended = true;
    }

    @Override
    public void writeStartElement(String prefix, String local, String uri) throws XMLStreamException
    {
        super.writeStartElement(prefix, local, uri);
        appendNamespaces();
    }


/* These are not called:
    @Override
    public void writeNamespace(String prefix, String uri) throws XMLStreamException
    {
        System.out.println("prefix=" + prefix +", uri=" + uri);

        if(!xpathNamespaceContexts.containsKey(prefix))
        {

            super.writeNamespace(prefix, uri);
        }

        appendNamespaces();

    }

    @Override
    public void writeDefaultNamespace(String uri) throws XMLStreamException
    {
        System.out.println("prefix='', uri=" + uri);

        if(!xpathNamespaceContexts.containsKey(""))
        {
            super.writeDefaultNamespace(uri);
        }
        appendNamespaces();
    }

    @Override
    public void writeStartElement(String uri, String local) throws XMLStreamException
    {
        System.out.println("uri=" + uri +", local="+local);
        super.writeStartElement(uri, local);
    }

    @Override
    public void writeStartElement(String local) throws XMLStreamException
    {
        System.out.println("local="+local);
        super.writeStartElement(local);
    }
     */

    @Override
    public void setDefaultNamespace(String uri)
    {
        throw UNSUPPORTED_OPERATION_EXCEPTION;
    }

    @Override
    public void setNamespaceContext(NamespaceContext ctx)
    {
        throw UNSUPPORTED_OPERATION_EXCEPTION;
    }

    @Override
    public void setPrefix(String pfx, String uri)
    {
        throw UNSUPPORTED_OPERATION_EXCEPTION;
    }
}
