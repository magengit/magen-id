jQuery(document).ready(function () {
	var scopesLeft=[]
	var scopesRight=[]
	if(jQuery("#default_scopes").val()==''){
		jQuery("#default_scopes").val('')
	}


		 jQuery("#add_client_btn").click(function () {
			 jQuery("#selectedscopes_id option").each(function () {
           scopesRight=addItemToArray(scopesRight,jQuery(this).clone().val())
			 });
			 jQuery("#default_scopes").val(scopesRight.join())
			 //jQuery('#client_edit_form').submit();
		 });

		 jQuery("#client_cancel_btn").click(function () {
			 windows.location="/clients"
		 });

		jQuery("#btnleft").click(function () {

				jQuery("#allscopes option:selected").each(function () {
					if(!exist(scopesRight,jQuery(this).clone().val())){
						jQuery("#selectedscopes_id").append(jQuery(this).clone());
						//scopesRight=addItemToArray(scopesRight,jQuery(this).clone().val())
						//scopesLeft=addItemToArray(scopesLeft,jQuery(this).clone().val())
					}


						//jQuery(this).remove();
				});
				//jQuery("#default_scopes").val(scopesRight.join())
		});

		jQuery("#btnright").click(function () {
				jQuery("#selectedscopes_id option:selected").each(function () {
					  //scopesRight=addItemToArray(scopesRight,jQuery(this).clone().val())
						//scopesLeft=addItemToArray(scopesLeft,jQuery(this).clone().val())
						jQuery(this).remove();
				});
				//jQuery("#default_scopes").val(scopesRight.join())
		});
});

function exist(arr,item){
	var i = arr.indexOf(item);
	if(i != -1) {
		return true;
	}
	return false;
}

function removeItemFromArray(arr,item){
	var i = arr.indexOf(item);
	if(i != -1) {
		arr.splice(i, 1);
	}
	return arr;
}
function addItemToArray(arr,item){
	console.log(item)
	console.log(arr.length)

	var i = arr.indexOf(item);
	console.log(i)
	if(i == -1) {
		arr.push(item)
	} else{
		arr.splice(i, 1);
	}
	return arr;
}
