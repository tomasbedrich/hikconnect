def ppxml(xml_string):
    import xml.dom.minidom

    return xml.dom.minidom.parseString(xml_string).toprettyxml(newl="", indent=4 * " ")


def ppjson(json_string):
    import json

    return json.loads(json_string).dumps(indent=4)
