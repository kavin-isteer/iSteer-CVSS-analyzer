package com.isteer.repository.dao;

import java.util.List;

import com.isteer.entity.Dependency;

public interface DependencyRepositoryDao {
	
	/** * Saves the given dependency to the database.
	 * 
	 * @param dependency The dependency to save.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public int save(Dependency dependency);
	/** * Saves the given dependency to the database.
	 * 
	 * @param dependency The dependency to save.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public List<Dependency> findAll();
	/** * Retrieves all dependencies from the database.
	 * 
	 * @return A list of all dependencies.
	 */
	public Dependency findByUuid(String uuid);
	/** * Finds a dependency by its UUID.
	 * 
	 * @param uuid The UUID of the dependency to find.
	 * @return The dependency with the specified UUID, or null if not found.
	 */
	public Dependency findByDependencyUuid(String uuid);
	/** * Finds a dependency by its UUID.
	 * 
	 * @param uuid The UUID of the dependency to find.
	 * @return The dependency with the specified UUID, or null if not found.
	 */
	public int update(String uuid, Dependency dependency);
	/** * Updates the dependency with the specified UUID.
	 * 
	 * @param uuid The UUID of the dependency to update.
	 * @param dependency The dependency data to update.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public int softDelete(String uuid);
	

}
