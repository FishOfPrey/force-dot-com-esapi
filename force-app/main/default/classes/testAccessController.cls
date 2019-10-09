/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - Salesforce.com
 * 
 * The Apex ESAPI implementation is published by Salesforce.com under the New BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Yoel Gluck (securecloud .at. salesforce.com) <a href="http://www.salesforce.com">Salesforce.com</a>
 * @created 2010
 */

/**
 * This class contains unit tests for validating the behavior of Apex classes
 * and triggers.
 *
 * Unit tests are class methods that verify whether a particular piece
 * of code is working properly. Unit test methods take no arguments,
 * commit no data to the database, and are flagged with the testMethod
 * keyword in the method definition.
 *
 * All test methods in an organization are executed whenever Apex code is deployed
 * to a production organization to confirm correctness, ensure code
 * coverage, and prevent regressions. All Apex classes are
 * required to have at least 75% code coverage in order to be deployed
 * to a production organization. In addition, all triggers must have some code coverage.
 * 
 * The @isTest class annotation indicates this class only contains test
 * methods. Classes defined with the @isTest annotation do not count against
 * the organization size limit for all Apex scripts.
 *
 * See the Apex Language Reference for more information about Testing and Code Coverage.
 */
@isTest
private class testAccessController {

    static testMethod void testAccessControl() {
        Contact c = new Contact();
        c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name 
        String errStr;
        
        try {
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
           	
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
        	
	    	ESAPI.accessController().getCreatableFields(c);
	    	ESAPI.accessController().getUpdateableFields(c);
	    	ESAPI.accessController().getViewableFields(c);

	    	ESAPI.accessController().getCreatableFields(Contact.getSObjectType());
	    	ESAPI.accessController().getUpdateableFields(Contact.getSObjectType());
	    	ESAPI.accessController().getViewableFields(Contact.getSObjectType());
        	
        	c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().updateAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITHOUT);
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.INHERIT);
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c.LastName = 'ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
        
        SFDCAccessController ac = new SFDCAccessController(SFDCAccessController.SharingMode.WITHOUT, SFDCAccessController.OperationMode.ALL_OR_NONE);
        ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        
        try {
        	ESAPI.accessController().setOperationMode(null);
        	System.assert(false, 'Should never get here');
        } catch (Exception e) {
        	// should fail - so all good
        }
        
        try {
        	ESAPI.accessController().setSharingMode(null);
        	System.assert(false, 'Should never get here');
        } catch (Exception e) {
        	// should fail - so all good
        }
        
        try {
        	c = new Contact();
        	c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(false);
			string fieldNameThatDoesNotExist = 'LastName123DOESNOTEXIST';
        	ESAPI.accessController().insertAsUser(c, new List<String>{fieldNameThatDoesNotExist}); // The requested field doesn't exist.
        	
        	System.assert(false, 'Should never get here. Not expecting access to field LastName123DOESNOTEXIST');
        } catch (SFDCAccessControlException e) {
        	// should fail - so all good
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 

			System.assertEquals('NO_CREATE', e.getExceptionReason() + '');
			System.assertEquals('Access Violation', e.getText());
			System.assertEquals('FIELD_ACCESS_VIOLATION', e.getExceptionType() + '');

			//System.assert(false, 'TEMP a : ' + e);  
        }
    }

	// No access to sObject at all
	@isTest
	static void runasProfileNoCreatesObject_WithoutStripping() {
		runasProfileNoCreatesObject_Internal(false, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObject_WithStripping() {
		runasProfileNoCreatesObject_Internal(true, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObjects_WithoutStripping() {
		runasProfileNoCreatesObject_Internal(false, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObjects_WithStripping() {
		runasProfileNoCreatesObject_Internal(true, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	static void runasProfileNoCreatesObject_Internal(boolean enableStripping, boolean asCollection) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access'];  //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');

		System.runAs(u) {
			try {
				Contact c = new Contact();
				c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3';
				
				ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
				ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
				ESAPI.accessController().setStripInaccessibleActive(enableStripping);

				if(asCollection) {
					ESAPI.accessController().insertAsUser(new List<Contact>{c}, new List<String>{'LastName'});
				} else {
					ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
				}

				System.assert(false, 'Should never get here. Not expected to have create access for Contact');
			}  catch (SFDCAccessControlException e) {
				// should fail - so all good
				string errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
					+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
					+ e.getExceptionField() + ' Text: ' + e.getText(); 

				System.assertEquals('NO_CREATE', e.getExceptionReason() + '');
				System.assertEquals('Access Violation', e.getText());
				System.assertEquals('OBJECT_ACCESS_VIOLATION', e.getExceptionType() + '');

				//System.assert(false, 'TEMP a : ' + e);  
			}
		}
	}

	// No update access on the sObject
	@isTest
	static void runasProfileNoUpdatesObject_WithoutStripping() {
		runasProfileNoUpdatesObject_Internal(false, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoUpdatesObject_WithStripping() {
		runasProfileNoUpdatesObject_Internal(true, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoUpdatesObjects_WithoutStripping() {
		runasProfileNoUpdatesObject_Internal(false, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoUpdatesObjects_WithStripping() {
		runasProfileNoUpdatesObject_Internal(true, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	static void runasProfileNoUpdatesObject_Internal(boolean enableStripping, boolean asCollection) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access'];  //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');

		System.runAs(u) {
			try {
				Contact c = new Contact();
				c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3';
				insert c;
				
				ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
				ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
				ESAPI.accessController().setStripInaccessibleActive(enableStripping);

				if(asCollection) {
					ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
				} else {
					ESAPI.accessController().updateAsUser(new Map<Id, Contact>{c.Id => c}, new List<String>{'LastName'});
				}

				System.assert(false, 'Should never get here. Not expected to have update access for Contact');
			}  catch (SFDCAccessControlException e) {
				// should fail - so all good
				string errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
					+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
					+ e.getExceptionField() + ' Text: ' + e.getText(); 

				System.assertEquals('NO_UPDATE', e.getExceptionReason() + '');
				System.assertEquals('Access Violation', e.getText());
				System.assertEquals('OBJECT_ACCESS_VIOLATION', e.getExceptionType() + '');

				//System.assert(false, 'TEMP a : ' + e);  
			}
		}
	}

	// No access to field on sObject create
	@isTest
	static void runasProfileNoCreatesObjectField_WithoutStripping() {
		runasProfileNoCreatesObjectField_Internal(false, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObjectField_WithStripping() {
		runasProfileNoCreatesObjectField_Internal(true, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObjectsField_WithoutStripping() {
		runasProfileNoCreatesObjectField_Internal(false, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoCreatesObjectsField_WithStripping() {
		runasProfileNoCreatesObjectField_Internal(true, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	// No access to field on sObject create
	static void runasProfileNoCreatesObjectField_Internal(boolean enableStripping, boolean asCollection) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only
		System.debug('readOnlyProfileId:' + readOnlyProfileId);

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = true,
																	PermissionsDelete = false,
																	PermissionsEdit = true,
																	PermissionsRead = true
																);
		insert contactObjectPermission;

		FieldPermissions emailFieldPermission = new FieldPermissions(SobjectType ='Contact',
																Field = 'Contact.Email',
																ParentId = ps.Id,
																PermissionsRead = true,
																PermissionsEdit = false
															);	
		FieldPermissions contactFieldPermission = new FieldPermissions(SobjectType ='Contact',
																Field = 'Contact.Description',
																ParentId = ps.Id,
																PermissionsRead = true,
																PermissionsEdit = true
															);
		insert new FieldPermissions[]{emailFieldPermission, contactFieldPermission};

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			try {
				Contact c = new Contact();
				c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3';
				c.Email = u.Email;
				c.Description = 'Desc';

				System.assert(SObjectType.Contact.createable);
				//System.assert(SObjectType.Contact.fields.Name.isCreateable(), 'Name should be Createable');
				System.assert(SObjectType.Contact.fields.Email.isAccessible(), 'The Contact.Email field should be Accessible.');
				System.assert(!SObjectType.Contact.fields.Email.isCreateable(), 'The Contact.Email field should not be Createable. Just Readable');
				System.assert(SObjectType.Contact.fields.Description.isCreateable());
				
				ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
				ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
				ESAPI.accessController().setStripInaccessibleActive(enableStripping);

				if(asCollection) {
					ESAPI.accessController().insertAsUser(new List<Contact>{c}, new List<String>{'LastName', 'Description', 'Email'});
				} else {
					ESAPI.accessController().insertAsUser(c, new List<String>{'LastName', 'Description', 'Email'});
				}

				System.assert(false, 'Should never get here. Not expected to have permission to insert the Contact.Email field');
			}  catch (SFDCAccessControlException e) {
				// should fail - so all good
				string errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
					+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
					+ e.getExceptionField() + ' Text: ' + e.getText(); 

				System.assertEquals('NO_CREATE', e.getExceptionReason() + '');
				System.assertEquals('Access Violation', e.getText());
				System.assertEquals('FIELD_ACCESS_VIOLATION', e.getExceptionType() + '');
				System.assertEquals('Contact', e.getExceptionObject() + '');
				System.assertEquals('email', e.getExceptionField() + '');

				//System.assert(false, 'TEMP a : ' + errStr);  
			}
		}
	}

	//#region Update
	// No access to field on sObject update
	@isTest
	static void runasProfileNoUpdatesObjectField_WithoutStripping() {
		runasProfileNoUpdatesObjectField_Internal(false, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}
	@isTest
	static void runasProfileNoUpdatesObjectField_WithStripping() {
		runasProfileNoUpdatesObjectField_Internal(true, false);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	@isTest
	static void runasProfileNoUpdatesObjectsField_WithoutStripping() {
		runasProfileNoUpdatesObjectField_Internal(false, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}
	@isTest
	static void runasProfileNoUpdatesObjectsField_WithStripping() {
		runasProfileNoUpdatesObjectField_Internal(true, true);
		//System.assert(false, 'CPU Time:' + limits.getCpuTime() + '\nDML:' + limits.getDMLRows() + '\nHeap:' + limits.getHeapSize() + '\nQueries:' + limits.getQueries());
	}

	static void runasProfileNoUpdatesObjectField_Internal(boolean enableStripping, boolean asCollection) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = true,
																	PermissionsDelete = false,
																	PermissionsEdit = true,
																	PermissionsRead = true
																);
		insert contactObjectPermission;

		FieldPermissions emailFieldPermission = new FieldPermissions(SobjectType ='Contact',
																Field = 'Contact.Email',
																ParentId = ps.Id,
																PermissionsRead = true,
																PermissionsEdit = false
															);	
		// 'AccountId', 'LastName','FirstName','Salutation','Name', 'ReportsToId', 'OwnerId', 'LastActivityDate','LastCURequestDate','LastCUUpdateDate','LastViewedDate','LastReferencedDate', 'EmailBouncedReason','EmailBouncedDate','IsEmailBounced', 'PhotoUrl', 'JigsawContactId'
		List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus'};
		// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
		readWriteFields.add('OtherAddress');
		// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
		readWriteFields.add('MailingAddress');
		
		List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);
		
		readWritePerms.add(emailFieldPermission);

		insert readWritePerms;

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			try {
				Contact c = new Contact();
				c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3';
				c.Email = u.Email;
				c.Description = 'Desc';
				insert c;

				System.assert(SObjectType.Contact.createable);
				//System.assert(SObjectType.Contact.fields.Name.isCreateable(), 'Name should be Createable');
				System.assert(!SObjectType.Contact.fields.Email.isCreateable());
				System.assert(!SObjectType.Contact.fields.Email.isUpdateable()); 
				System.assert(SObjectType.Contact.fields.Description.isCreateable());
				System.assert(SObjectType.Contact.fields.Description.isUpdateable());
				System.assert(SObjectType.Contact.fields.OtherStreet.isCreateable());
				System.assert(SObjectType.Contact.fields.MailingGeocodeAccuracy.isUpdateable()); 
				
				ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
				ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
				ESAPI.accessController().setStripInaccessibleActive(enableStripping);
				// AccountId, 'Name', 'OtherGeocodeAccuracy', 'MailingAddress', 'MailingGeocodeAccuracy','ReportsToId'

				if(asCollection) {
					ESAPI.accessController().updateAsUser(new Map<Id, Contact>{c.Id => c}, new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'});
				} else {
					ESAPI.accessController().updateAsUser(c, new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'});
				}

				System.assert(false, 'Should never get here. Not expected to have permission to update the Contact.Email field');
			}  catch (SFDCAccessControlException e) {
				// should fail - so all good
				string errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
					+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
					+ e.getExceptionField() + ' Text: ' + e.getText(); 

				System.assertEquals('NO_UPDATE', e.getExceptionReason() + '');
				System.assertEquals('Access Violation', e.getText());
				System.assertEquals('FIELD_ACCESS_VIOLATION', e.getExceptionType() + '');
				System.assertEquals('Contact', e.getExceptionObject() + '');
				System.assertEquals('email', e.getExceptionField() + '', 'Expected to have no access to the Contact.Email field');
 
			}
		}
	}
	//#endregion

	private static List<FieldPermissions> createFieldPermissions(string sObjectType, Id permissionSetId, boolean read, boolean edit, List<string> readWriteFields) {
		List<FieldPermissions> fieldPerms = new List<FieldPermissions>();
		for(string fieldName : readWriteFields) {
			FieldPermissions contactFieldPermission = new FieldPermissions(SobjectType = sObjectType,
																Field = sObjectType + '.' + fieldName,
																ParentId = permissionSetId,
																PermissionsRead = read,
																PermissionsEdit = edit
															);
			fieldPerms.add(contactFieldPermission);
		}
		return fieldPerms;
	}

	//#region isAuthorizedToView
	@IsTest
	static void runasProfileNotAuthorizedToViewSObject_WithStripping() {
		runasProfileNotAuthorizedToViewSObject_Internal(true);
	}

	@IsTest
	static void runasProfileNotAuthorizedToViewSObject_WithoutStripping() {
		runasProfileNotAuthorizedToViewSObject_Internal(false);
	}

	static void runasProfileNotAuthorizedToViewSObject_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		// ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
		// 															ParentId = ps.Id,
		// 															PermissionsCreate = false,
		// 															PermissionsDelete = false,
		// 															PermissionsEdit = false,
		// 															PermissionsRead = false
		// 														);
		// insert contactObjectPermission;

		

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			
			boolean isAccessible = ESAPI.accessController().isAuthorizedToView(Schema.Contact.getSobjectType(), new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'});
			System.assert(!isAccessible, 'Not expecting to have access to view Contact records');
		}
	}

	@IsTest
	static void runasProfileNotAuthorizedToViewSObjectField_WithStripping() {
		runasProfileNotAuthorizedToViewSObjectField_Internal(true);
	}

	@IsTest
	static void runasProfileNotAuthorizedToViewSObjectField_WithoutStripping() {
		runasProfileNotAuthorizedToViewSObjectField_Internal(false);
	}

	static void runasProfileNotAuthorizedToViewSObjectField_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = false,
																	PermissionsDelete = false,
																	PermissionsEdit = false,
																	PermissionsRead = true
																);
		insert contactObjectPermission;	

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			
			List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus'};
			// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
			readWriteFields.add('OtherAddress');
			// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
			readWriteFields.add('MailingAddress');
			
			List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);
			insert readWritePerms;

			List<String> fieldsToCheck = new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus'};
			// Not expected to have access to the Email field
			fieldsToCheck.add('Email');
			System.assert(!SObjectType.Contact.fields.Email.isCreateable());
			System.assert(!SObjectType.Contact.fields.Email.isUpdateable()); 

			boolean isAccessible = ESAPI.accessController().isAuthorizedToView(Schema.Contact.getSobjectType(), fieldsToCheck);
			System.assert(!isAccessible, 'Not expecting to have access to view Contact Email fields');

			List<Schema.SObjectField> schemaSObjectFields = schemaSObjectFields(Schema.Contact.getSobjectType(), fieldsToCheck);

			isAccessible = ESAPI.accessController().isAuthorizedToView(Schema.Contact.getSobjectType(), schemaSObjectFields);
			System.assert(!isAccessible, 'Not expecting to have access to view Contact Email records');
		}
	}
	//#endregion

	//#region isAuthorizedToCreate
	@IsTest
	static void runasProfileNotAuthorizedToCreateSObject_WithStripping() {
		runasProfileNotAuthorizedToCreateSObject_Internal(true);
	}

	@IsTest
	static void runasProfileNotAuthorizedToCreateSObject_WithoutStripping() {
		runasProfileNotAuthorizedToCreateSObject_Internal(false);
	}

	static void runasProfileNotAuthorizedToCreateSObject_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = false,
																	PermissionsDelete = false,
																	PermissionsEdit = false,
																	PermissionsRead = true
																);
		insert contactObjectPermission;	

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			
			List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus'};
			// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
			readWriteFields.add('OtherAddress');
			// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
			readWriteFields.add('MailingAddress');
			
			List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);
			insert readWritePerms;

			List<String> fieldsToCheck = new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'};

			boolean isAccessible = ESAPI.accessController().isAuthorizedToCreate(Schema.Contact.getSobjectType(), fieldsToCheck);
			System.assert(!isAccessible, 'Not expecting to have access to Create Contact records');
		}
	}

	@IsTest
	static void runasProfileAuthorizedToCreateSObject_WithStripping() {
		runasProfileAuthorizedToCreateSObject_Internal(true);
	}

	@IsTest
	static void runasProfileAuthorizedToCreateSObject_WithoutStripping() {
		runasProfileAuthorizedToCreateSObject_Internal(false);
	}

	static void runasProfileAuthorizedToCreateSObject_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = true,
																	PermissionsDelete = false,
																	PermissionsEdit = false,
																	PermissionsRead = true
																);
		insert contactObjectPermission;	

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus', 'Email'};
		// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
		readWriteFields.add('OtherAddress');
		// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
		readWriteFields.add('MailingAddress');

		List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);

		insert readWritePerms;

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			

			List<String> fieldsToCheck = new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'};

			boolean isAccessible = ESAPI.accessController().isAuthorizedToCreate(Schema.Contact.getSobjectType(), fieldsToCheck);
			System.assert(isAccessible, 'Expecting to have access to Create Contact records');
		}
	}
	//#endregion

	//#region isAuthorizedToUpdate
	@IsTest
	static void runasProfileNotAuthorizedToUpdateSObject_WithStripping() {
		runasProfileNotAuthorizedToUpdateSObject_Internal(true);
	}

	@IsTest
	static void runasProfileNotAuthorizedToUpdateSObject_WithoutStripping() {
		runasProfileNotAuthorizedToUpdateSObject_Internal(false);
	}

	static void runasProfileNotAuthorizedToUpdateSObject_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = false,
																	PermissionsDelete = false,
																	PermissionsEdit = false,
																	PermissionsRead = true
																);
		insert contactObjectPermission;	

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			
			List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus'};
			// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
			readWriteFields.add('OtherAddress');
			// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
			readWriteFields.add('MailingAddress');
			
			List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);
			insert readWritePerms;

			List<String> fieldsToCheck = new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'};

			boolean isAccessible = ESAPI.accessController().isAuthorizedToUpdate(Schema.Contact.getSobjectType(), fieldsToCheck);
			System.assert(!isAccessible, 'Not expecting to have access to Update Contact records');
		}
	}

	@IsTest
	static void runasProfileAuthorizedToUpdateSObject_WithStripping() {
		runasProfileAuthorizedToUpdateSObject_Internal(true);
	}

	@IsTest
	static void runasProfileAuthorizedToUpdateSObject_WithoutStripping() {
		runasProfileAuthorizedToUpdateSObject_Internal(false);
	}

	static void runasProfileAuthorizedToUpdateSObject_Internal(boolean enableStripping) {
		// Built in System profile
		Profile readOnlyProfileId = [SELECT Id FROM Profile WHERE Name='No Access']; //Read Only

		User u = new User(Alias = 'standt', Email='standarduser@esapi.com', 
            EmailEncodingKey='UTF-8', LastName='Testing', LanguageLocaleKey='en_US', 
            LocaleSidKey='en_US', ProfileId = readOnlyProfileId.Id, 
            TimeZoneSidKey='America/Los_Angeles', UserName='standarduser@esapi.com');
		insert u;

		PermissionSet ps = new PermissionSet(Label = 'mockPs', Name = 'mockPs');
		insert ps;

		// https://gist.github.com/soapboxjoe/8333202
		ObjectPermissions contactObjectPermission = new ObjectPermissions(SobjectType = 'Contact',
																	ParentId = ps.Id,
																	PermissionsCreate = false,
																	PermissionsDelete = false,
																	PermissionsEdit = true,
																	PermissionsRead = true
																);
		insert contactObjectPermission;	

		PermissionSetAssignment psa = new PermissionSetAssignment(PermissionSetId = ps.Id, AssigneeId = u.Id);
		insert psa; 

		List<string> readWriteFields = new List<String>{'Account','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','Title','Department','AssistantName','LeadSource','Birthdate','Description','Jigsaw','CleanStatus', 'Email'};
		// OtherAddress - 'OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','OtherGeocodeAccuracy',
		readWriteFields.add('OtherAddress');
		// MailingAddress - 'MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','MailingGeocodeAccuracy'
		readWriteFields.add('MailingAddress');

		List<FieldPermissions> readWritePerms = createFieldPermissions('Contact', ps.Id, true, true, readWriteFields);

		insert readWritePerms;

		System.runAs(u) {
			ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
			ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
			ESAPI.accessController().setStripInaccessibleActive(enableStripping);
			

			List<String> fieldsToCheck = new List<String>{'LastName','FirstName','Salutation','OtherStreet','OtherCity','OtherState','OtherPostalCode','OtherCountry','OtherLatitude','OtherLongitude','MailingStreet','MailingCity','MailingState','MailingPostalCode','MailingCountry','MailingLatitude','MailingLongitude','Phone','Fax','MobilePhone','HomePhone','OtherPhone','AssistantPhone','ReportsToId','Title','Department','AssistantName','LeadSource','Birthdate','Description','OwnerId','EmailBouncedReason','EmailBouncedDate','Jigsaw','CleanStatus', 'Email'};

			boolean isAccessible = ESAPI.accessController().isAuthorizedToUpdate(Schema.Contact.getSobjectType(), fieldsToCheck);
			System.assert(isAccessible, 'Expecting to have access to Update Contact records');
		}
	}
	//#endregion
    
	private static List<Schema.SObjectField> schemaSObjectFields(Schema.SObjectType someType, List<string> fields) {
		List<Schema.SObjectField> schemaFields = new List<Schema.SObjectField>();

		Map<String, Schema.SObjectField> fieldMap = someType.getDescribe().fields.getMap();

		for(string fieldName : fields) {
       		schemaFields.add(fieldMap.get(fieldName));
    	}

		return schemaFields;
	}

    static testMethod void testReturnedObjects() {
     	/* test return object and id with strings */
    	Contact tmp;
    	Contact tmp2;
    	Contact tmp3;
    	Contact tmp4;
        Contact c1 = new Contact();
        c1.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1'; // We add this long random to make sure we will not conflict with any real last name 
    	tmp = (Contact)ESAPI.accessController().insertAsUser(c1, new List<String>{'LastName'});
    	tmp2 = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1' limit 1];
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];
        	
    	System.assert(tmp != null, 'insertAsUser returned null');
    	System.assert(tmp2 != null, 'select with LastName after insertAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after insertAsUser returned null');
        	
    	System.assert(tmp.id == tmp2.id, 'select with LastName after insertAsUser returned id which is not equal to id from returned object');
    	System.assert(tmp.id == tmp3.id, 'select with tmp.id after insertAsUser returned id which is not equal to id from returned object');
        	
    	tmp.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1 updated';
    	tmp4 = (Contact)ESAPI.accessController().updateAsUser(tmp, new List<String>{'LastName'});
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];

    	System.assert(tmp4 != null, 'updateAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after updateAsUser returned null');
        	
    	System.assert(tmp.id == tmp4.id, 'id from returned object after updateAsUser is not equal to id from original returned object from insertAsUser');
    	System.assert(tmp.id == tmp3.id, 'id from select with id from original reurned object after insertAsUser, is not equal to id from original returned object from insertAsUser');
        	
    	System.assert(tmp.LastName == tmp3.LastName, 'c1.LastName == tmp3.LastName');
    	System.assert(tmp.LastName == tmp4.LastName, 'c1.LastName == tmp4.LastName');

    	/* test return object and id with Schema.SObjectField */
        c1 = new Contact();
        c1.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1'; // We add this long random to make sure we will not conflict with any real last name 
    	tmp = (Contact)ESAPI.accessController().insertAsUser(c1, new List<Schema.SObjectField>{Contact.LastName});
    	tmp2 = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1' limit 1];
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];
        	
    	System.assert(tmp != null, 'insertAsUser returned null');
    	System.assert(tmp2 != null, 'select with LastName after insertAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after insertAsUser returned null');
        	
    	System.assert(tmp.id == tmp2.id, 'select with LastName after insertAsUser returned id which is not equal to id from returned object');
    	System.assert(tmp.id == tmp3.id, 'select with tmp.id after insertAsUser returned id which is not equal to id from returned object');
        	
    	tmp.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1 updated';
    	tmp4 = (Contact)ESAPI.accessController().updateAsUser(tmp, new List<Schema.SObjectField>{Contact.LastName});
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];

    	System.assert(tmp4 != null, 'updateAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after updateAsUser returned null');
        	
    	System.assert(tmp.id == tmp4.id, 'id from returned object after updateAsUser is not equal to id from original returned object from insertAsUser');
    	System.assert(tmp.id == tmp3.id, 'id from select with id from original reurned object after insertAsUser, is not equal to id from original returned object from insertAsUser');
        	
    	System.assert(tmp.LastName == tmp3.LastName, 'c1.LastName == tmp3.LastName');
    	System.assert(tmp.LastName == tmp4.LastName, 'c1.LastName == tmp4.LastName');
    }
    
    static testMethod void testAccessControlArray() {
        String errStr;
        
        try {
        	// test with sharing
	        Contact c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray1 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        Contact c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        Contact [] arr = new Contact[]{c1, c2};
	        Database.SaveResult [] results;
	        
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	results = ESAPI.accessController().insertAsUser(arr, new List<Schema.SObjectField>{Contact.LastName}).getResults();
        	
        	System.assert(results.size() == 2, 'Could not insert two objects into db #1');
        	System.assert(results[0].isSuccess() == true, 'Could not insert first object into db #1 [0] - ' + results[0].getErrors());
        	System.assert(results[0].isSuccess() == true, 'Could not insert first object into db #1 [1] - ' + results[0].getErrors());
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #1');
			
			arr[0].LastName = 'ESAPI TestArray1 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<Schema.SObjectField>{Contact.LastName});
        	ESAPI.accessController().deleteAsUser(arr);
        	
        	// test without sharing
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITHOUT);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #2');
			
			arr[0].LastName = 'ESAPI TestArray3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(arr);

        	// test inherit sharing
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.INHERIT);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #3');
			
			arr[0].LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(arr);
        	
        	// test results class
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	
        	SFDCAccessControlResults.InsertResults insertResults;
        	sObject [] insertedObjects;
        	
        	insertResults = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'});
        	
        	System.assert(insertResults.wasSuccessful() == true, 'insertResults.wasSuccessful() == true');
        	
        	results = insertResults.getResults();
        	System.assert(results.size() == 2, 'results.size() == 2');
        	
        	insertedObjects = insertResults.getInsertedObjects();
        	System.assert(insertedObjects.size() == 2, 'insertedObjects.size() == 2');
        	System.assert(insertedObjects[0].Id == results[0].getId(), 'insertedObjects[0].Id == results[0].getId()');
        	System.assert(insertedObjects[1].Id == results[1].getId(), 'insertedObjects[1].Id == results[1].getId()');
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #3');
			
			arr[0].LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';

        	SFDCAccessControlResults.UpdateResults updateResults;
        	sObject [] updatedObjects;
        	
        	updateResults = ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});

        	System.assert(updateResults.wasSuccessful() == true, 'updateResults.wasSuccessful() == true');
        	
        	results = updateResults.getResults();
        	System.assert(results.size() == 2, 'results.size() == 2');
        	
        	updatedObjects = updateResults.getUpdatedObjects();
        	System.assert(updatedObjects.size() == 2, 'updatedObjects.size() == 2');
        	System.assert(updatedObjects[0].Id == results[0].getId(), 'updatedObjects[0].Id == results[0].getId()');
        	System.assert(updatedObjects[1].Id == results[1].getId(), 'updatedObjects[1].Id == results[1].getId()');
        	
        	SFDCAccessControlResults.DeleteResults deleteResults;
        	deleteResults = ESAPI.accessController().deleteAsUser(arr);
        	
        	System.assert(deleteResults.wasSuccessful() == true, 'deleteResults.wasSuccessful() == true');
        	
        	Database.DeleteResult [] delResults = deleteResults.getResults();
        	System.assert(delResults.size() == 2, 'delResults.size() == 2');
        	
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
    }
    
    static testMethod void testAccessControlConstructor() {
        String errStr;
        
        try {
	        SFDCAccessController ac = new SFDCAccessController(SFDCAccessController.SharingMode.WITHOUT, SFDCAccessController.OperationMode.ALL_OR_NONE, SFDCAccessController.OperationMode.ALL_OR_NONE);
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
    }
    
    static testMethod void testLimits() {
    	/* This test is to confirm the new functions we added (insertAsUser and updateAsUser) 
    	   that use Schema.SObjectField indded solve the fields limiters issue. (fields has a limit of 10 calls)
    	   Now that we removed this limit, we should be able to call these functions until we hit the next type of
    	   limiter, this is likely to be DML operations which are capped at 100. This is why we are testing up to 100 */
    	   
    	Integer max = 100;
    	
    	for (Integer i = 0; i < max; i++) {
    		Contact c = new Contact();
    		c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c limits'; // We add this long random to make sure we will not conflict with any real last name
    		ESAPI.accessController().insertAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
    	}
    	
    	Contact [] arr = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c limits'];
    	
    	System.assert(arr.size() == max, 'testLimits');
    }
}