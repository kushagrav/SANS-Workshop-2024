package aws.validation

import rego.v1

deny_rdsencryption contains {
	# Our error message specific to the policy
	"msg": "RDS should have storage encryted",
	"details": {"rds_encryption": rds_encryption}, # If the policy fails, output which resources caused the violation
} if {
	# this takes the values returned from the block and assigns it to data_resources
	data_resources := [resource |
		# this loops over the resources in input.planned_values.root_module
		some resource in input.planned_values.root_module.resources

		# this is a conditional on if the resource should be returned. in this case it checks
		# if it is type aws_db_instance
		resource.type in {"aws_db_instance"}
	]

	# this takes the values returned from the block and assigns it to rds_encryption
	# -> these are our failing resources
	rds_encryption := [rds.name |
		# loop over the data_resources that were set above
		some rds in data_resources

		# return values whose storage_encrypted is not true
		rds.values.storage_encrypted != true
	]

	# this is a print statement for debugging
	print("hello debugging")

	# If the count of resources with storage_encrypted=true is not zero we fail
	# Remember: In rego 'true' is a failure
	count(rds_encryption) != 0
}
