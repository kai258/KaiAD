function youkufilm(){
	var testingText = 'youkuVIP("brief-score","player");'
	var rootElement = document.body;
	var newElement = document.createElement("script");
	var newElementHtmlContent = document.createTextNode(testingText);
	rootElement.appendChild(newElement);
	newElement.appendChild(newElementHtmlContent);
}
