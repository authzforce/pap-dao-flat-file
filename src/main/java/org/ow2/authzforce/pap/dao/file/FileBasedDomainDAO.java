/**
 * Copyright (C) 2012-2015 Thales Services SAS.
 *
 * This file is part of AuthZForce.
 *
 * AuthZForce is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * AuthZForce is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with AuthZForce. If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * 
 */
package org.ow2.authzforce.pap.dao.file;

import java.io.IOException;

import org.ow2.authzforce.core.pap.api.dao.DomainDAO;
import org.ow2.authzforce.core.pap.api.dao.PolicyDAOClient;
import org.ow2.authzforce.core.pap.api.dao.PolicyVersionDAOClient;

interface FileBasedDomainDAO<VERSION_DAO_CLIENT extends PolicyVersionDAOClient, POLICY_DAO_CLIENT extends PolicyDAOClient> extends
		DomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>
{

	/**
	 * Reload PDP from policy repository
	 * 
	 * @throws IllegalArgumentException
	 *             Invalid PDP configuration files (e.g. policies or PDP configuration)
	 * @throws IOException
	 *             Problem getting PDP configuration files from repository
	 */
	void reloadPDP() throws IOException, IllegalArgumentException;

}
