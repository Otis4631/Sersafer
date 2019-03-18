$(document).ready(function() {
  // $('#example').DataTable( {
  //     "ajax": 'as.txt'
  // } );
	loadDataOnReady();
	loadDataOnClick();
	// changeSteps();
	// nextStep();
	finishWizard(function() {
			//ON FINISH EVENT
	});

});
function loadDataOnReady()
{
	var wizardContent = $('.wizard-content');
	//Get "data-for" attribute and find element
	var dataFor = $('.wizard-menu .fa-circle-o.active').attr('data-for');
	var elementFor = $(dataFor);
	var dataLoad = elementFor.attr('data-load');
}

function loadDataOnClick()
{
	var wizardButtons = $('.wizard-menu .fa-circle-o');
	var wizardContent = $('.wizard-content');

	wizardButtons.on('click', function(event) {
			event.preventDefault();
			//Change active state
			wizardButtons.removeClass('active');
			$(this).addClass('active');


			//Get "data-for" attribute and find element
			var dataFor = $(this).attr('data-for');
			var elementFor = $(dataFor);

			var dataLoad = elementFor.attr('data-load');

//        Check if attribute does exist
//        If true then load ajax, else load from div
			if (typeof dataLoad !== 'undefined' && dataLoad !== false)
			{
				//Load content ajax
          $('#example').DataTable( {
            bDestroy:true,
            ajax: dataLoad
    } );
			}
			else
			{
				alert("kong");
					// wizardContent.html(elementFor.html());

			}
	});
}
