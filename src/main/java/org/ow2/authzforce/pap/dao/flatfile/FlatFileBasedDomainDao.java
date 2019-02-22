/**
 * Copyright (C) 2012-2019 THALES.
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
/**
 * 
 */
package org.ow2.authzforce.pap.dao.flatfile;

import java.io.Closeable;
import java.io.IOException;

import org.ow2.authzforce.core.pap.api.dao.DomainDao;
import org.ow2.authzforce.core.pap.api.dao.PolicyDaoClient;
import org.ow2.authzforce.core.pap.api.dao.PolicyVersionDaoClient;
import org.ow2.authzforce.pap.dao.flatfile.xmlns.DomainProperties;

interface FlatFileBasedDomainDao<VERSION_DAO_CLIENT extends PolicyVersionDaoClient, POLICY_DAO_CLIENT extends PolicyDaoClient>
		extends DomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>, Closeable
{
	/**
	 * Get domain's (internal) unique ID (set by the domains DAO)
	 * 
	 * @return domain ID
	 */
	String getDomainId();

	/**
	 * Get domain's external ID (set by provisioning client)
	 * 
	 * @return external ID
	 */
	String getExternalId();

	/**
	 * Synchronize domain (PDP in particular) with domain directory
	 * 
	 * @return up-to-date domain properties (after sync)
	 * 
	 * @throws IllegalArgumentException
	 *             Invalid PDP configuration files (e.g. policies or PDP configuration)
	 * @throws IOException
	 *             Problem getting PDP configuration files from repository
	 */
	DomainProperties sync() throws IOException, IllegalArgumentException;

}
