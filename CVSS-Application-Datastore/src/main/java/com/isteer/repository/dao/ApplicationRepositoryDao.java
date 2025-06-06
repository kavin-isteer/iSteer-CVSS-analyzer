package com.isteer.repository.dao;

import java.util.List;

import com.isteer.entity.Application;

public interface ApplicationRepositoryDao {
	
	/** * Saves the given application to the database.
	 * 
	 * @param application The application to save.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public int save(Application application);
	
	/** * Retrieves all applications from the database.
	 * 
	 * @return A list of all applications.
	 */
	public List<Application> findAll();
	
	/** * Finds an application by its UUID.
	 * 
	 * @param uuid The UUID of the application to find.
	 * @return The application with the specified UUID, or null if not found.
	 */
	public Application findByApplicationUuid(String uuid);

	/** * Finds an application by its UUID.
	 * 
	 * @param uuid The UUID of the application to find.
	 * @return The application with the specified UUID, or null if not found.
	 */
	public Application findByUuid(String uuid);
	
	/** * Updates the application with the specified UUID.
	 * 
	 * @param uuid The UUID of the application to update.
	 * @param application The application data to update.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public int update(String uuid, Application application);
	
	/** * Soft deletes the application with the specified UUID.
	 * 
	 * @param uuid The UUID of the application to soft delete.
	 * @return The number of rows affected, or a negative value if an error occurs.
	 */
	public int softDelete(String uuid);

}
